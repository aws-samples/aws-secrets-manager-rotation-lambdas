# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)


""" 
This Lambda Function rotates the password for an Directory Services user account
and rotates the corresponding secret stored in Secrets Manager. Specifically, this 
function updates the password for an existing user rather than creating a new 
user. This means that there is a shot period of time when the password in 
Directory Services does not match the secret in Secrets Manager. Consumers of
the secret should be aware of this and implement a retry after a short wait if
authentication fails. You can read more about this here:
https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-lambda-function-customizing.html

The Secrets Manager secret should include three key/value pairs stored as JSON. 
For example, the default secret looks like this:
    {
      "DirectoryId": "d-1234567890",
      "Username": "WebServiceAccount",
      "Password": "SuperSecretPassword123!"
    }
You can override the keys using environment variables. For example, Systems 
Manager Seamless Domain Join uses 'awsSeamlessDomainDirectoryId', 
'awsSeamlessDomainUsername', and 'awsSeamlessDomainPassword' as key names 
within the secret. 
"""
dict_key_directory = os.environ['DICT_KEY_DIRECTORY'] if 'DICT_KEY_DIRECTORY' in os.environ else 'DirectoryId'
dict_key_username  = os.environ['DICT_KEY_USERNAME']  if 'DICT_KEY_USERNAME'  in os.environ else 'UserName'
dict_key_password  = os.environ['DICT_KEY_PASSWORD']  if 'DICT_KEY_PASSWORD'  in os.environ else 'NewPassword'


def lambda_handler(event, context):
    """
    Rotates a password for a Directory Services user account. This is the main lambda entry point.
    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
        context (LambdaContext): The Lambda runtime information
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not properly configured for rotation
        KeyError: If the event parameters do not contain the expected keys
    """
    # Log the event that was received for reference
    logger.info("Received event: %s" % event)
    
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the clients
    secrets_manager_client = boto3.client('secretsmanager')
    directory_services_client = boto3.client('ds')
    
    # Make sure the version is staged correctly
    metadata = secrets_manager_client.describe_secret(SecretId=arn)
    
    if "RotationEnabled" in metadata and not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    # Call the appropriate step
    if step == "createSecret":
        create_secret(secrets_manager_client, arn, token)

    elif step == "setSecret":
        set_secret(secrets_manager_client, directory_services_client, arn, token)

    elif step == "testSecret":
        test_secret(secrets_manager_client, arn, token)

    elif step == "finishSecret":
        finish_secret(secrets_manager_client, arn, token)

    else:
        logger.error("lambda_handler: Invalid step parameter %s for secret %s" % (step, arn))
        raise ValueError("Invalid step parameter %s for secret %s" % (step, arn))


def create_secret(secrets_manager_client, arn, token):
    """
    Creates a new secret and labels it AWSPENDING. This is the first step in the rotation. 
    It only creates he pending secret in Secrets Manger. It does NOT update Directory Services. That 
    will happen in the next step, setSecret. This method first checks for the existence of a pending 
    secret for the passed in token. If one does not exist, it will generate a new secret.
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Make sure the current secret exists
    current_dict = get_secret_dict(secrets_manager_client, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except secrets_manager_client.exceptions.ResourceNotFoundException:
        # Get exclude characters from environment variable
        exclude_characters = os.environ['EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else ':/@"\'\\'
        # Generate a random password
        passwd = secrets_manager_client.get_random_password(ExcludeCharacters=exclude_characters)
        current_dict[dict_key_password] = passwd['RandomPassword']

        # Put the secret
        secrets_manager_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(secrets_manager_client, directory_services_client, arn, token):
    """
    Set the secret in Directory Services. This is the second step, where Directory Services
    is actually updated. This method does not update the Secret Manager label. Therefore, the 
    AWSCURRENT secret does not match the password in Directory Services as the end of this 
    step. We are technically in a broken state at the end of this step. It will be fixed in the 
    finishSecret step when the Secrets Manager value is updated. 
    Args:
        secrets_manager_client (client): The secrets manager service client
        directory_services_client (client): The directory services client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON or unable to set password in Directory Services
        KeyError: If the secret json does not contain the expected keys
    """
    # Get the pending secret and update password in Directory Services
    pending_dict = get_secret_dict(secrets_manager_client, arn, "AWSPENDING", token)
    try:
        directory_services_client.reset_user_password(
            DirectoryId=pending_dict[dict_key_directory], 
            UserName=pending_dict[dict_key_username], 
            NewPassword=pending_dict[dict_key_password]
        )
    except:
        logger.error("setSecret: Unable to reset the users password in Directory Services for directory %s and user %s" % (pending_dict[dict_key_directory], pending_dict[dict_key_username]))
        raise ValueError("Unable to reset the users password in Directory Services for arn %s" % arn)


def test_secret(secrets_manager_client, arn, token):
    """
    This is a placeholder for testing the secret before finishing the rotation. It would require 
    that the Lambda function is deployed in a VPC, which this sample is not. 
    Args:
        secrets_manager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version
    """
    return #Always succeed


def finish_secret(secrets_manager_client, arn, token):
    """
    Finish the rotation by marking the pending secret as current. This is the final step. 
    This method finishes the secret rotation by staging the secret staged AWSPENDING with the AWSCURRENT stage.
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
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secrets_manager_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


def get_secret_dict(secrets_manager_client, arn, stage, token=None):
    """
    Gets the secret dictionary corresponding for the secret arn, stage, and token
    This helper function gets credentials for the arn and stage passed in and returns the dictionary 
    by parsing the JSON string. You can change the default dictionary keys using env vars above.
    Args:
        service_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired
        stage (string): The stage identifying the secret version
    Returns:
        SecretDictionary: Secret dictionary
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON
    """
    required_fields = [dict_key_directory, dict_key_username, dict_key_password]
    
    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = secrets_manager_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = secrets_manager_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    # Parse and return the secret JSON string
    return secret_dict