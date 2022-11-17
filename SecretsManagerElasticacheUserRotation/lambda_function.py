# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Secrets Manager Elasticache User Handler

    This handler rotates ElastiCache user password. Once executed it creates a new version of
    a Secret with a generated password and calls ElastiCache modify user API to update user password.
    As soon as changes get applied and user state became ‘active’, the new password could be used to
    authentication with Cache clusters.

    We recommend paying special attention to Lambda function permissions to prevent privilege escalation
    and use one Lambda function to rotate a single secret.

    Required Lambda function environment variables are the following:
        - SECRETS_MANAGER_ENDPOINT: The service endpoint of secrets manager, for example https://secretsmanager.us-east-1.amazonaws.com
        - SECRET_ARN: The ARN of secret created in Secrets Manager
        - USER_NAME: Username of the ElastiCache user

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        UserNotFoundFault: If the user associated to the secret does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys

    """
    secret_arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    env_secret_arn = os.environ['SECRET_ARN']
    if secret_arn != env_secret_arn:
        logger.error("Secret %s is not allowed to use this Lambda function for rotation" % secret_arn)
        raise ValueError("Secret %s is not allowed to use this Lambda function for rotation" % secret_arn)

    # Setup the clients
    secrets_manager_service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = secrets_manager_service_client.describe_secret(SecretId=secret_arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % secret_arn)
        raise ValueError("Secret %s is not enabled for rotation" % secret_arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, secret_arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, secret_arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, secret_arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, secret_arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, secret_arn))

    if step == "createSecret":
        create_secret(secrets_manager_service_client, secret_arn, token)
    elif step == "setSecret":
        set_secret(secrets_manager_service_client, secret_arn, token)
    elif step == "testSecret":
        test_secret(secrets_manager_service_client, secret_arn)
    elif step == "finishSecret":
        finish_secret(secrets_manager_service_client, secret_arn, token)
    else:
        logger.error("lambda_handler: Invalid step parameter %s for secret %s" % (step, secret_arn))
        raise ValueError("Invalid step parameter %s for secret %s" % (step, secret_arn))


def create_secret(secrets_manager_service_client, secret_arn, token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        secrets_manager_service_client (client): The secrets manager service client

        secret_arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

    """
    # Make sure the current secret exists
    current_secret = get_secret_dict(secrets_manager_service_client, secret_arn, "AWSCURRENT")

    # Verify if the username stored in environment variable is the same with the one stored in current_secret
    verify_user_name(current_secret)

    user_context = resource_arn_to_context(current_secret["user_arn"])
    elasticache_service_client = boto3.client('elasticache', region_name=user_context["region"])

    # validates if user exists
    elasticache_service_client.describe_users(UserId=user_context["resource"])

    # Now try to get the secret version, if that fails, put a new secret
    try:
        secrets_manager_service_client.get_secret_value(SecretId=secret_arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s." % secret_arn)
    except secrets_manager_service_client.exceptions.ResourceNotFoundException:
        # Get exclude characters from environment variable
        exclude_characters = os.environ['EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else '/@"\'\\'
        # Get password length from environment variable
        password_length = int(os.environ['PASSWORD_LENGTH']) if 'PASSWORD_LENGTH' in os.environ else 20
        # Generate a random password
        passwd = secrets_manager_service_client.get_random_password(ExcludeCharacters=exclude_characters, PasswordLength=password_length)
        current_secret['password'] = passwd['RandomPassword']

        # Put the secret
        secrets_manager_service_client.put_secret_value(SecretId=secret_arn, ClientRequestToken=token, SecretString=json.dumps(current_secret),
                                                        VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (secret_arn, token))


def set_secret(secrets_manager_service_client, secret_arn, token):
    """Set the secret

    This method waits for elasticache user to be in a modifiable state ('active'), and set the AWSPENDING and AWSCURRENT secrets in the user.

    Args:
        secrets_manager_service_client (client): The secrets manager service client

        secret_arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        UserNotFoundFault: If the user associated to the secret does not exist

    """
    # Make sure the current secret exists
    current_secret = get_secret_dict(secrets_manager_service_client, secret_arn, "AWSCURRENT")
    pending_secret = get_secret_dict(secrets_manager_service_client, secret_arn, "AWSPENDING", token)
    user_context = resource_arn_to_context(current_secret["user_arn"])

    # Verify if the username stored in environment variable is the same with the one stored in pending_secret
    verify_user_name(pending_secret)

    passwords = [pending_secret["password"]]
    # During the first rotation the password might not be present in the current version
    if "password" in current_secret:
        passwords.append(current_secret["password"])

    # creating elasticache client
    elasticache_service_client = boto3.client('elasticache', region_name=user_context["region"])
    # wait user to be in a modifiable state
    user = wait_for_user_be_active("setSecret", elasticache_service_client, user_context["resource"], secret_arn)
    # update user passwords
    elasticache_service_client.modify_user(UserId=user["UserId"], Passwords=passwords)
    logger.info("setSecret: Successfully set password for user %s in elasticache for secret arn %s." % (current_secret["user_arn"], secret_arn))


def test_secret(secrets_manager_service_client, secret_arn):
    """Test the secret

    This method waits for the elasticache user to be in `active` state. It means that the password was propagated to all associated instances, if any.

    Args:
        secrets_manager_service_client (client): The secrets manager service client

        secret_arn (string): The secret ARN or other identifier

    Raises:
        UserNotFoundFault: If the user associated to the secret does not exist

    """
    current_secret = get_secret_dict(secrets_manager_service_client, secret_arn, "AWSCURRENT")
    user_context = resource_arn_to_context(current_secret["user_arn"])
    # creating elasticache client
    elasticache_service_client = boto3.client('elasticache', region_name=user_context["region"])
    # wait password propagation
    wait_for_user_be_active("testSecret", elasticache_service_client, user_context["resource"], secret_arn)
    logger.info("testSecret: User %s is active in elasticache after password update for secret arn %s." % (current_secret["user_arn"], secret_arn))


def finish_secret(secrets_manager_service_client, secret_arn, token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        secrets_manager_service_client (client): The secrets manager service client

        secret_arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist

    """
    # First describe the secret to get the current version
    metadata = secrets_manager_service_client.describe_secret(SecretId=secret_arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, secret_arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secrets_manager_service_client.update_secret_version_stage(SecretId=secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=token,
                                                               RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, secret_arn))


def wait_for_user_be_active(step, elasticache_service_client, user_id, secret_arn):
    """ Waits for user to be in 'active' state

    This method calls describe_users api in a loop until it reaches the timeout or the user status is 'active'

    Args:
        step: The current step name

        elasticache_service_client: The elasticache service client

        user_id: The user id

        secret_arn (string): The secret ARN or other identifier

    Returns:
        User: The user returned by elasticache service client

    Raises:
        ValueError: If the user does not get active within the defined time

        UserNotFoundFault: If the user does not exist

    """

    max_waiting_time = int(os.environ['MAX_WAITING_TIME_FOR_ACTIVE_IN_SECONDS']) if 'MAX_WAITING_TIME_FOR_ACTIVE_IN_SECONDS' in os.environ else 600
    retry_interval = int(os.environ['WAITING_RETRY_INTERVAL_IN_SECONDS']) if 'WAITING_RETRY_INTERVAL_IN_SECONDS' in os.environ else 10
    timeout = time.time() + max_waiting_time

    while timeout > time.time():
        user = elasticache_service_client.describe_users(UserId=user_id)["Users"][0]
        if user["Status"] == "active":
            logger.info("%s: user %s active, exiting." % (step, user_id))
            return user
        logger.info("%s: user %s not active, waiting." % (step, user_id))
        time.sleep(retry_interval)

    logger.error("%s: user %s associated with secret %s did not reached the active status." % (step, user_id, secret_arn))
    raise ValueError("%s: user %s associated with secret %s did not reached the active status." % (step, user_id, secret_arn))


def get_secret_dict(secrets_manager_service_client, secret_arn, stage, token=None):
    """Gets the secret dictionary corresponding for the secret secret_arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        secrets_manager_service_client (client): The secrets manager service client

        secret_arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        stage (string): The stage identifying the secret version

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        KeyError: If the secret has no user_arn

    """
    # Only do VersionId validation against the stage if a token is passed in
    if token is None:
        secret = secrets_manager_service_client.get_secret_value(SecretId=secret_arn, VersionStage=stage)
    else:
        secret = secrets_manager_service_client.get_secret_value(SecretId=secret_arn, VersionId=token, VersionStage=stage)
    plaintext = secret['SecretString']
    try:
        secret_dict = json.loads(plaintext)
    except Exception:
        # wrapping json parser exceptions to avoid possible  password disclosure
        logger.error("Invalid secret value json for secret %s." % (secret_arn))
        raise ValueError("Invalid secret value json for secret %s." % (secret_arn))

    # Validates if there is a user associated to the secret
    if "user_arn" not in secret_dict:
        logger.error("createSecret: secret %s has no user_arn defined." % (secret_arn))
        raise KeyError("createSecret: secret %s has no user_arn defined." % (secret_arn))

    return secret_dict


def resource_arn_to_context(arn):
    '''Returns a dictionary built based on the user arn

    Args:
        arn (string): The user ARN
    Returns:
        dict: A user arn dictionary with fields present in the arn
    '''
    elements = arn.split(':')
    result = {
        'arn': elements[0],
        'partition': elements[1],
        'service': elements[2],
        'region': elements[3],
        'account': elements[4],
        'resource_type': elements[5],
        'resource': elements[6]
    }
    return result


def verify_user_name(secret):
    '''Verify whether USER_NAME set in Lambda environment variable matches what's set in the secret

    Args:
        secret: The secret from Secrets Manager
    Raises:
        verificationException: username in Lambda environment variable doesn't match the one stored in the secret
    '''
    env_elasticache_user_name = os.environ['USER_NAME']
    secret_user_name = secret["username"]
    if env_elasticache_user_name != secret_user_name:
        logger.error("User %s is not allowed to use this Lambda function for rotation" % secret_user_name)
        raise ValueError("User %s is not allowed to use this Lambda function for rotation" % secret_user_name)
