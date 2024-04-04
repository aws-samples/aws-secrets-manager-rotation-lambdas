# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from json import JSONDecodeError
from typing import Final
import boto3
from utils import KeytabManager

"""
Simple Authentication Security Layer (SASL) provides developers of applications
and shared libraries with mechanisms for authentication, data integrity-checking,
and encryption.
The SASL_PATH variable must be set in Unix environments in order to be used by
libraries and applications that depend on SASL libraries. In this case, these
libraries are deployed alongside this code, thus we set the SASL_PATH to the
current working directory.
"""
os.environ['SASL_PATH'] = os.getcwd()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

"""
This Lambda Function rotates the password for an Directory Services user account
and rotates the corresponding secret stored in Secrets Manager. Specifically,
this function updates the password for an existing user rather than creating
a new user. This means that there is a short period of time when the password in
Directory Services does not match the secret in Secrets Manager. Consumers of
the secret should be aware of this and implement a retry after a short wait if
authentication fails (note that the pending and previous secrets are available 
with the version labels AWSPENDING and AWSPREVIOUS could also be tried on failure).
You can read more about this here:
https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets
-lambda-function-customizing.html

The Secrets Manager secret should include three key/value pairs stored as JSON.
For example, the default secret looks like this:
    {
      "DirectoryId": "d-1234567890",
      "Username": "WebServiceAccount",
      "Password": "SuperSecretPassword123!"
    }
You can override the keys using environment variables for use-cases other than
Seamless Domain Join.
For example, Systems Manager Seamless Domain Join uses
'awsSeamlessDomainDirectoryId',
'awsSeamlessDomainUsername', and 'awsSeamlessDomainPassword' as key names
within the secret.

Important Notes:
  #1 Kerberos needs DNS, please change DHCP options set to use domain name.
  #2 This Lambda must be connected to the same VPC as your Directory Services
  directory.
  #3 For Directory Services please add corresponding route to internet
  gateway for AWS APIs.
  #4 The pre-initialized secret must match AD credentials.

"""
# If DICT_KEY_USERNAME, DICT_KEY_USERNAME are set, this
# password rotation can be used for other users.
DICT_KEY_DIRECTORY = os.environ.get(
    "DICT_KEY_DIRECTORY") or "awsSeamlessDomainDirectoryId"
DICT_KEY_USERNAME = os.environ.get(
    "DICT_KEY_USERNAME") or "awsSeamlessDomainUsername"
DICT_KEY_PASSWORD = os.environ.get(
    "DICT_KEY_PASSWORD") or "awsSeamlessDomainPassword"
DICT_KEY_LAST_MODIFIED = os.environ.get(
    "DICT_KEY_LAST_MODIFIED") or "lastModifiedDateTime"
DICT_KEY_SCHEMA_VERSION = os.environ.get(
    "DICT_KEY_SCHEMA_VERSION") or "schemaVersion"
DICT_KEY_KEYTAB_ARNS = os.environ.get(
    "DICT_KEY_KEYTAB_ARNS") or "keytabArns"

# Dictionary keys for keytab secrets
DICT_KEY_KEYTAB_NAME = os.environ.get(
    "DICT_KEY_KEYTAB_NAME") or "name"
DICT_KEY_KEYTAB_PRINCIPALS = os.environ.get(
    "DICT_KEY_KEYTAB_PRINCIPALS") or "principals"
DICT_KEY_KEYTAB_CONTENTS = os.environ.get(
    "DICT_KEY_KEYTAB_CONTENTS") or "keytabContents"
DICT_KEY_KEYTAB_VERSION = os.environ.get(
    "DICT_KEY_KEYTAB_VERSION") or "version"
# parentSecretArn maps a keytab secret back to the ARN
# of the secret that references it
DICT_KEY_SECRET_ARN = os.environ.get(
    "DICT_KEY_SECRET_ARN") or "parentSecretArn"

KINIT_CURRENT_CREDS_SUCCESSFUL: Final = "KINIT_USING_CURRENT_CREDS_SUCCESSFUL"
KINIT_PENDING_CREDS_SUCCESSFUL: Final = "KINIT_USING_PENDING_CREDS_SUCCESSFUL"
EXCLUDE_CHARACTERS: Final = "/@\"'\\"


def lambda_handler(event, context):
    """
    Rotates a password for a Directory Services user account. This is the
    main lambda entry point.
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must
        include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret,
            testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
        stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
        Exceptions from ds.describe_directories :
            DirectoryService.Client.exceptions.EntityDoesNotExistException
            DirectoryService.Client.exceptions.InvalidParameterException
            DirectoryService.Client.exceptions.InvalidNextTokenException
            DirectoryService.Client.exceptions.ClientException
            DirectoryService.Client.exceptions.ServiceException
    """
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    # To use only the packaged kerberos libraries.
    os.environ["LD_LIBRARY_PATH"] = "./:$LD_LIBRARY_PATH"

    # Setup the clients
    secrets_manager_client = boto3.client(
        "secretsmanager", endpoint_url=os.environ["SECRETS_MANAGER_ENDPOINT"]
    )
    directory_services_client = boto3.client("ds")

    # Make sure the version is staged correctly
    metadata = secrets_manager_client.describe_secret(SecretId=arn)
    if "RotationEnabled" in metadata and not metadata["RotationEnabled"]:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)

    current_dict = get_secret_dict(secrets_manager_client, arn, "AWSCURRENT")
    directory_name_list = [current_dict[DICT_KEY_DIRECTORY]]
    directory_info = directory_services_client.describe_directories(
        DirectoryIds=directory_name_list, Limit=1
    )
    directory_description = directory_info["DirectoryDescriptions"][0]
    directory_name = directory_description["Name"]

    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        logger.error(
            "Secret version %s has no stage for rotation of secret %s." % (token, arn)
        )
        raise ValueError(
            "Secret version %s has no stage for rotation of secret %s." % (token, arn)
        )
    if "AWSCURRENT" in versions[token]:
        logger.info(
            "Secret version %s already set as AWSCURRENT for secret %s." % (token, arn)
        )
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error(
            "Secret version %s not set as AWSPENDING for rotation of secret %s."
            % (token, arn)
        )
        raise ValueError(
            "Secret version %s not set as AWSPENDING for rotation of secret %s."
            % (token, arn)
        )

    # Call the appropriate step
    if step == "createSecret":
        logger.info('Creating Secret')
        create_secret(secrets_manager_client, arn, token, directory_name, current_dict)
    elif step == "setSecret":
        logger.info('Setting Secret')
        # Get the pending secret and update password in Directory Services
        pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        if current_dict[DICT_KEY_USERNAME] != pending_dict[DICT_KEY_USERNAME]:
            logger.error(
                "Username %s in current dict does not match username %s in "
                "pending dict"
                % (current_dict[DICT_KEY_USERNAME], pending_dict[DICT_KEY_USERNAME])
            )
            raise ValueError(
                "Username %s in current dict does not match username %s in "
                "pending dict"
                % (current_dict[DICT_KEY_USERNAME], pending_dict[DICT_KEY_USERNAME])
            )
        pending_directory_name_list = [pending_dict[DICT_KEY_DIRECTORY]]
        if pending_directory_name_list != directory_name_list:
            logger.error(
                "Current directory name list %s does not match pending "
                "directory name list %s"
                % (directory_name_list, pending_directory_name_list)
            )
            raise ValueError(
                "Current directory name list %s does not match pending "
                "directory name list %s"
                % (directory_name_list, pending_directory_name_list)
            )
        set_secret(
            directory_services_client,
            directory_name,
            current_dict,
            pending_dict,
            secrets_manager_client,
            arn,
            token
        )
        set_keytab(
            secrets_manager_client,
            arn,
            token,
            directory_name,
            pending_dict,
        )

    elif step == "testSecret":
        logger.info('Testing Secret')
        # Test updated password
        pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        test_secret(directory_name, pending_dict, secrets_manager_client, token)

    elif step == "finishSecret":
        logger.info('Finishing Secret')
        finish_secret(secrets_manager_client, arn, token)

    else:
        logger.error(
            "lambda_handler: Invalid step parameter %s for secret %s" % (step, arn)
        )
        raise ValueError("Invalid step parameter %s for secret %s" % (step, arn))


def create_secret(secrets_manager_client, arn, token, directory_name, current_dict):
    """
    Creates a new secret and labels it AWSPENDING. This is the first step in
    the rotation.
    It only creates the pending secret in Secrets Manager. It does NOT update
    Directory Services. That
    will happen in the next step, setSecret. This method first checks for the
    existence of a pending
    secret for the passed in token. If one does not exist, it will generate a
    new secret.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret
        directory_name (string): Directory name used for kinit
        current_dict (dictionary): Used for kinit operations
    Raises:
        ValueError: Raise exception if kinit fails with given credentials
    """

    # Exception if kinit fails
    execute_kinit_command(current_dict, None, directory_name)

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except secrets_manager_client.exceptions.ResourceNotFoundException:
        exclude_characters = os.environ.get("EXCLUDE_CHARACTERS", EXCLUDE_CHARACTERS)
        # Generate a random password
        passwd = secrets_manager_client.get_random_password(
            ExcludeCharacters=exclude_characters
        )
        current_dict[DICT_KEY_PASSWORD] = passwd["RandomPassword"]
        current_dict[DICT_KEY_LAST_MODIFIED] = get_current_datetime()

        # Put the secret
        secrets_manager_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(current_dict),
            VersionStages=["AWSPENDING"],
        )
        logger.info(
            "createSecret: Successfully put secret for ARN %s and version %s."
            % (arn, token)
        )


def set_secret(directory_services_client, directory_name, current_dict, pending_dict, secrets_manager_client, arn, token):
    """
    Set the secret in Directory Services, then set the keytab secret(s) in Secrets Manager.
    This is the second step, where Directory Services
    is actually updated. This method does not update the Secret Manager
    label. Therefore, the AWSCURRENT secret does not match the password in
    Directory Services at the end of this step.
    We are technically in a broken state at the end of this step. It
    will be fixed in the
    finishSecret step when the Secrets Manager value is updated.

    Args:
        directory_services_client (client): The directory services client
        directory_name (string): Directory name used for kinit
        current_dict (dictionary): Used for kinit operations
        pending_dict (dictionary): Used to reset Directory Services password
        secrets_manager_client (client): The Secrets Manager client
        arn (string): Arn of the keytab secret being rotated
        token (string): The ClientRequestToken associated with the secret
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
        stage does not exist
        ValueError: If the secret is not valid JSON or unable to set password
        in Directory Services
        KeyError: If the secret json does not contain the expected keys
        ValueError: Raise exception if kinit fails with given credentials
    """

    # Make sure current or pending credentials work
    status = execute_kinit_command(current_dict, pending_dict, directory_name)
    # Cover the case where this step has already succeeded and
    # AWSCURRENT is no longer the current password, try to log in
    # with the AWSPENDING password and if that is successful, immediately
    # return.
    if status == KINIT_PENDING_CREDS_SUCCESSFUL:
        return

    try:
        directory_services_client.reset_user_password(
            DirectoryId=pending_dict[DICT_KEY_DIRECTORY],
            UserName=pending_dict[DICT_KEY_USERNAME],
            NewPassword=pending_dict[DICT_KEY_PASSWORD],
        )
    except Exception as directory_service_exception:
        logger.error(
            "setSecret: Unable to reset the user's password in Directory "
            "Services for directory %s and user %s"
            % (pending_dict[DICT_KEY_DIRECTORY], pending_dict[DICT_KEY_USERNAME])
        )
        raise ValueError(
            "Unable to reset the user's password in Directory Services"
        ) from directory_service_exception


def set_keytab(secrets_manager_client, arn, token, directory_name, pending_dict):
    """
    Set the keytab secret(s) in Secrets Manager. This is part of the second step,
    where Directory Services is updated as keytabs are dependent upon the
    credentials stored there.
    Args:
        secrets_manager_client (client): The Secrets Manager client
        arn (string): Arn of the keytab secret being rotated
        token (string): The ClientRequestToken associated with the secret
        directory_name (string): Directory name the credentials belong to
        pending_dict (dictionary): Contains user credentials and keytab arns
    Raises:
        Exception: If a keytab fails to generate, validate, or update in SecretsManager
    """
    try:
        logger.info("Setting the new keytab value(s)...")
        username = pending_dict[DICT_KEY_USERNAME]
        password = pending_dict[DICT_KEY_PASSWORD]
        user_principal = KeytabManager.get_user_principal(username, directory_name)

        with KeytabManager() as kt_manager:
            try:
                # Create a master keytab file containing credentials for all of the user's principals
                master_keytab_data = kt_manager.generate_new_keytab_file(username, password, user_principal,
                                                                         directory_name)
            except Exception:
                logger.error("Failed to create keytab with new password")
                raise

            # Each keytab has its own ARN. Each keytab will be rotated one at a time.
            keytab_arns = pending_dict[DICT_KEY_KEYTAB_ARNS]
            keytabs_failed_to_set = []
            for keytab_arn in keytab_arns:
                try:
                    keytab_dict, stage = get_pending_or_current_keytab_dict(secrets_manager_client, keytab_arn, token)

                    # If pending keytab dict exists, keytab has already been rotated
                    if stage == "AWSPENDING":
                        continue

                    # Validate the existing principals against the keytab's principals
                    validate_principals(kt_manager, keytab_dict, keytab_arn)

                    # Rotate keytab
                    principals = keytab_dict[DICT_KEY_KEYTAB_PRINCIPALS]
                    split_keytab = kt_manager.split_keytab(master_keytab_data, principals, user_principal)

                    # Update the AWSPENDING dictionary with the new keytab and other values
                    keytab_dict[DICT_KEY_KEYTAB_CONTENTS] = split_keytab
                    keytab_dict[DICT_KEY_DIRECTORY] = pending_dict[DICT_KEY_DIRECTORY]
                    keytab_dict[DICT_KEY_SECRET_ARN] = arn
                    keytab_dict[DICT_KEY_LAST_MODIFIED] = get_current_datetime()

                    # Initialize or update the keytab version
                    if DICT_KEY_KEYTAB_VERSION in keytab_dict:
                        keytab_dict[DICT_KEY_KEYTAB_VERSION] += 1
                    else:
                        keytab_dict[DICT_KEY_KEYTAB_VERSION] = 1

                    # Put the secret with updated keytab
                    secrets_manager_client.put_secret_value(
                        SecretId=keytab_arn,
                        ClientRequestToken=token,
                        SecretString=json.dumps(keytab_dict),
                        VersionStages=["AWSPENDING"],
                    )
                    logger.info(
                        "setKeytab: Successfully put keytab secret for ARN %s and version %s."
                        % (keytab_arn, token)
                    )
                except Exception as e:
                    # Store any exceptions and raise them after each keytab is attempted to be set
                    keytabs_failed_to_set.append((keytab_arn, e))

            # If any of the keytabs failed to set, report them
            if keytabs_failed_to_set:
                error_strings = [f"Failed to set keytab for {len(keytabs_failed_to_set)}/{len(keytab_arns)} keytab(s):"]
                error_strings += [f"{arn}: {exception}" for arn, exception in keytabs_failed_to_set]
                full_error_message = os.linesep.join(error_strings)
                raise Exception(full_error_message)
    except Exception as keytab_exception:
        logger.error(
            "setSecret: Failed to set the user's keytab "
            "for directory %s, user %s, and arn %s. %s"
            % (pending_dict[DICT_KEY_DIRECTORY], pending_dict[DICT_KEY_USERNAME], arn, keytab_exception)
        )
        raise


def validate_principals(kt_manager: KeytabManager, keytab_dict: dict, keytab_arn: str):
    """
    Validates that the principals in the keytab match the principals defined in the secret.
    An error will be logged if:
        - Both principals and keytab are non-empty in the secret and the set of principals
          in the secret do not match the set of principals in the keytab
    A warning will be thrown if:
        - Principals were not specified in the secret
        - Keytab data is missing from the secret

    Args:
        kt_manager: Keytab manager instance
        keytab_dict: Dictionary of keytab secret
        keytab_arn: ARN of keytab secret
    """
    principals = keytab_dict.get(DICT_KEY_KEYTAB_PRINCIPALS)
    keytab_data = keytab_dict.get(DICT_KEY_KEYTAB_CONTENTS)
    if not principals:
        logger.warning("No principals to validate. If the list of principals and/or keytab were deleted in error or "
                       f"by an unauthorized party, please manually review the principals immediately. ARN: {keytab_arn}")
        return

    if not keytab_data:
        logger.warning("Principals of existing keytab could not be validated because keytab as empty or missing. "
                       "If the keytab was deleted in error or by an unauthorized party, please manually review the "
                       f"principals immediately. ARN: {keytab_arn}")
        return

    keytab_principals = kt_manager.get_principals_from_base64_keytab(keytab_data)
    if set(principals) != set(keytab_principals):
        raise Exception("Principals in secret do not match principals in keytab. "
                        "If the principals in secret were updated in error or by an unauthorized party, please "
                        "manually review the principals immediately."
                        f"\nSecret principals: {', '.join(sorted(principals))} "
                        f"\nKeytab principals: {', '.join(sorted(keytab_principals))} ")


def test_secret(directory_name, pending_dict, secrets_manager_client, token):
    """
    Args:
        directory_name (string) : Directory name
        pending_dict (dictionary): Used to test pending credentials
        secrets_manager_client (client): The secrets manager service client
        token (string): The ClientRequestToken associated with the secret
    Raises:
        Exception: Raise exception if kinit fails with given credentials or keytab(s)
    """
    try:
        # Test user and password
        execute_kinit_command(None, pending_dict, directory_name)

        # Test updated keytab(s)
        keytab_arns = pending_dict[DICT_KEY_KEYTAB_ARNS]
        username = pending_dict[DICT_KEY_USERNAME]
        user_principal = KeytabManager.get_user_principal(username, directory_name)
        test_keytabs(secrets_manager_client, token, keytab_arns, user_principal)
    except Exception:
        logger.error(
            "testSecret: One or more keytabs failed validation for "
            "directory %s and user %s"
            % (directory_name, pending_dict[DICT_KEY_USERNAME])
        )
        raise


def test_keytabs(secrets_manager_client, token, keytab_arns, user_principal):
    """
    Args:
        secrets_manager_client (client): The secrets manager service client
        token (string): The ClientRequestToken associated with the secret
        keytab_arns (list): The keytab ARNs or other identifiers
        user_principal (string): User principal of the keytabs
    Raises:
        Exception: Raise exception if any keytab fails to validate with kinit
    """
    with KeytabManager() as kt_manager:
        # Test keytabs for each arn associated with a password
        keytabs_failed_validation = []
        for keytab_arn in keytab_arns:
            secret_dict, stage = get_pending_or_current_keytab_dict(secrets_manager_client, keytab_arn, token)
            if stage == 'AWSCURRENT':
                logger.warning(
                    'Expected AWSPENDING stage for %s with version %s, but only AWSCURRENT was found.'
                    % (keytab_arn, token)
                )

            base64_encoded_keytab = secret_dict[DICT_KEY_KEYTAB_CONTENTS]
            try:
                kt_manager.validate_base64_encoded_keytab(base64_encoded_keytab, user_principal)
            except Exception as e:
                keytabs_failed_validation.append((keytab_arn, e))

        # If any keytab validations failed, report it
        if keytabs_failed_validation:
            error_strings = [f"Validation failed for {len(keytabs_failed_validation)}/{len(keytab_arns)} keytab(s):"]
            error_strings += [f"{arn}: {exception}" for arn, exception in keytabs_failed_validation]
            full_error_message = os.linesep.join(error_strings)
            raise ValueError(full_error_message)


def finish_secret(secrets_manager_client, arn, token):
    """
    Finish password rotation by marking the pending secret and pending secret
    as current.
    This method finishes the secret rotation by staging the secrets staged
    AWSPENDING with the AWSCURRENT stage.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    # First describe the secret to get the current version
    metadata = secrets_manager_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info(
                    "finishSecret: Version %s already marked as AWSCURRENT "
                    "for %s" % (version, arn)
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secrets_manager_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )

    logger.info(
        "finishSecret: Successfully set AWSCURRENT stage to version %s for "
        "secret %s." % (token, arn)
    )

    # Finish keytab(s)
    pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
    keytab_arns = pending_dict[DICT_KEY_KEYTAB_ARNS]
    finish_keytabs(secrets_manager_client, keytab_arns, token)


def finish_keytabs(secrets_manager_client, keytab_arns, token):
    """
    Finish keytab rotation by marking each pending secret in keytab_arns
    as current. This is the final step.
    This method finishes the secret rotation by staging the secrets staged
    AWSPENDING with the AWSCURRENT stage.
    Args:
        secrets_manager_client (client): The secrets manager service client
        keytab_arns (string): The keytab secret ARNs or other identifiers
        token (string): The ClientRequestToken associated with the secret version
    """

    # Finish each keytab
    for keytab_arn in keytab_arns:
        # First describe the secret to get the current version
        metadata = secrets_manager_client.describe_secret(SecretId=keytab_arn)
        current_version = None
        is_keytab_already_finished = False
        for version in metadata["VersionIdsToStages"]:
            if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
                if version == token:
                    is_keytab_already_finished = True
                    break
                current_version = version
                break

        # If current version is already marked as AWSCURRENT, skip to next keytab
        if is_keytab_already_finished:
            logger.info(
                "finishKeytab: Version %s already marked as AWSCURRENT "
                "for %s" % (current_version, keytab_arn)
            )
            continue

        # Finalize by staging the secret version current
        secrets_manager_client.update_secret_version_stage(
            SecretId=keytab_arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
        logger.info(
            "finishKeytab: Successfully set AWSCURRENT stage to version %s for "
            "secret %s." % (token, keytab_arn)
        )


def get_secret_dict(secrets_manager_client, arn, stage, token=None):
    """
    Gets the secret dictionary corresponding for the secret arn, stage,
    and token
    This helper function gets credentials for the arn and stage passed in and
    returns the dictionary
    by parsing the JSON string. You can change the default dictionary keys
    using env vars above.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret
        version, or None if no validation is desired
        stage (string): The stage identifying the secret version
    Returns:
        SecretDictionary: Secret dictionary
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and
        stage does not exist
        ValueError: If the secret is not valid JSON
    """
    required_fields = [DICT_KEY_DIRECTORY, DICT_KEY_USERNAME, DICT_KEY_PASSWORD, DICT_KEY_SCHEMA_VERSION, DICT_KEY_KEYTAB_ARNS]
    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = secrets_manager_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage=stage
        )
    else:
        secret = secrets_manager_client.get_secret_value(
            SecretId=arn, VersionStage=stage
        )

    try:
        plaintext = secret["SecretString"]
        secret_dict = json.loads(plaintext)
    except JSONDecodeError:
        raise Exception("Failed to parse secret string from %s" % arn)

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    # Parse and return the secret JSON string
    return secret_dict


def execute_kinit_command(current_dict, pending_dict, directory_name):
    """
    Executes the kinit command to verify user credentials.
    Args:
        current_dict (dictionary): Dictionary containing current credentials
        pending_dict (dictionary): Dictionary containing pending credentials
        directory_name (string): Directory name used for kinit command
    Returns:
        kinit_creds_successful or raises exception
    Raises:
        ValueError: Raise exception if kinit fails with given credentials
    """

    if pending_dict is not None:
        # First try to log in with the AWSPENDING password and if that is
        # successful, immediately return.
        with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as cache:
            username, password = check_inputs(pending_dict)
            try:
                proc = subprocess.Popen(
                    [
                        "./kinit",
                        "-c",
                        cache.name,
                        "%s@%s" % (username, directory_name.upper()),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    encoding="utf-8",
                    shell=False,
                )
                output, error = proc.communicate(input="%s\n" % password, timeout=15)
                if error is not None or proc.returncode != 0:
                    raise ValueError(
                        "kinit failed %d %s %s" % (proc.returncode, error, output)
                    )
                return KINIT_PENDING_CREDS_SUCCESSFUL
            except Exception:
                # If Pending secret does not authenticate, we can proceed to
                # current secret.
                logger.info(
                    "execute_kinit_command: Proceed to current secret since "
                    "pending secret "
                    "does not authenticate"
                )

    if current_dict is None:
        logger.error("execute_kinit_command: Unexpected value for current_dict")
        raise ValueError("execute_kinit_command: Unexpected value for current_dict")

    with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as cache:
        try:
            username, password = check_inputs(current_dict)
            proc = subprocess.Popen(
                [
                    "./kinit",
                    "-c",
                    cache.name,
                    "%s@%s" % (username, directory_name.upper()),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                encoding="utf-8",
                shell=False,
            )
            output, error = proc.communicate(input="%s\n" % password, timeout=15)
            if error is not None or proc.returncode != 0:
                raise ValueError(
                    "kinit failed %d %s %s" % (proc.returncode, error, output)
                )
            return KINIT_CURRENT_CREDS_SUCCESSFUL
        except Exception:
            logger.error("execute_kinit_command: kinit failed")
            raise ValueError("execute_kinit_command: kinit failed") from Exception


def check_inputs(dict_arg):
    """
    Check username and password for invalid characters
    Args:
        dict_arg (dictionary): Dictionary containing current credentials
    Returns:
        username(string): Username from Directory Service
        password(string): Password of username from Directory Service
    Raises:
        Value Error: If username or password has characters from exclude list.
    """
    username = dict_arg[DICT_KEY_USERNAME]
    password = dict_arg[DICT_KEY_PASSWORD]

    exclude_characters = os.environ.get("EXCLUDE_CHARACTERS", EXCLUDE_CHARACTERS)

    username_check_list = [char in username for char in exclude_characters]
    if True in username_check_list:
        raise ValueError("check_inputs: Invalid character in username")

    password_check_list = [char in password for char in exclude_characters]
    if True in password_check_list:
        raise ValueError("check_inputs: Invalid character in password")

    return username, password


def get_pending_or_current_keytab_dict(secrets_manager_client, keytab_arn, token):
    """
    Gets the secret dictionary corresponding for the keytab arn, stage,
    and token
    This helper function gets credentials for the arn and stage passed in and
    returns the dictionary
    by parsing the JSON string. You can change the default dictionary keys
    using env vars above.
    Args:
        secrets_manager_client (client): The secrets manager service client
        keytab_arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret
        version, or None if no validation is desired
    Returns:
        SecretDictionary (dict): Keytab secret dictionary
        Stage (string): Version stage
    Raises:
        Exception: If the keytab secret cannot be found in Secrets Manager
        stage does not exist
        KeyError: If schema of keytab secret is missing a required field
    """
    required_fields = [
        DICT_KEY_DIRECTORY,
        DICT_KEY_SCHEMA_VERSION,
        DICT_KEY_KEYTAB_NAME,
        DICT_KEY_KEYTAB_PRINCIPALS,
        DICT_KEY_KEYTAB_CONTENTS
    ]

    # Try getting the pending dictionary first. If this fails, fall back to current dictionary
    try:
        stage = "AWSPENDING"
        secret = secrets_manager_client.get_secret_value(
            SecretId=keytab_arn, VersionId=token, VersionStage=stage
        )
        logger.info("Successfully retrieved pending secret for %s." % keytab_arn)
    except (secrets_manager_client.exceptions.ResourceNotFoundException,
            secrets_manager_client.exceptions.InvalidRequestException):
        logger.info("Could not find AWSPENDING secret for %s. Defaulting to AWSCURRENT." % keytab_arn)
        try:
            stage = "AWSCURRENT"
            secret = secrets_manager_client.get_secret_value(
                SecretId=keytab_arn, VersionStage=stage
            )
            logger.info("Successfully retrieved current secret for %s." % keytab_arn)
        except secrets_manager_client.exceptions.ResourceNotFoundException as e:
            raise Exception("Failed to load secret from %s: %s" % (keytab_arn, e))

    try:
        plaintext = secret["SecretString"]
        secret_dict = json.loads(plaintext)
    except JSONDecodeError:
        raise Exception("Failed to parse secret string from %s" % keytab_arn)

    # validate secret schema
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    return secret_dict, stage


def get_current_datetime() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")