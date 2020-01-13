import boto3
import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    This lambda function rotates IAM access credentials.
    Prerequisites:
        - a "master" IAM user with permissions to iam:CreateAccessKey and iam:DeleteAccessKey for
          the IAM users in need of automated rotation
        - a "master" secret corresponding with the aforementioned master IAM user with JSON in the
          following format:
            {
                'accesskey': <required: the iam access key id associated with the master iam user>
                'secretkey': <required: the iam secret key id associated with the master iam user>
            }
        - the secret to be rotated has a SecretString as JSON string with the following format:
        {
            'username': <required: iam username>,
            'masterarn': <required: the arn of the master secret which will be used to manage access keys>
            'accesskey': <required: the iam access key id associated with this secret>
            'secretkey': <required: the iam secret key id associated with this secret>
        }
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
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    # Setup the client
    secretsmanager_client = boto3.client('secretsmanager')
    # Make sure the version is staged correctly
    metadata = secretsmanager_client.describe_secret(SecretId=arn)
    logging.info(repr(metadata))
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
    if step == "createSecret":
        logging.debug("createSecret %s" % arn)
        logging.info("for IAM user access keys secret creation is handled by IAM ")
    elif step == "setSecret":
        logging.debug("setSecret %s" % arn)
        current_dict = get_secret_dict(secretsmanager_client, arn, "AWSCURRENT", required_fields=['username'])
        username = current_dict['username']
        master_dict = get_secret_dict(secretsmanager_client, current_dict['masterarn'], "AWSCURRENT")
        master_iam_client = boto3.client('iam', aws_access_key_id=master_dict['accesskey'], aws_secret_access_key=master_dict['secretkey'])
        # load any pre-existing access keys. sorted by created descending. if the count is 2+ remove the oldest key
        existing_access_keys = sorted(master_iam_client.list_access_keys(UserName=username)['AccessKeyMetadata'], key=lambda x: x['CreateDate'])
        if len(existing_access_keys) >= 2:
            logger.info("at least 2 access keys already exist. deleting the oldest version: %s" % existing_access_keys[0]['AccessKeyId'])
            master_iam_client.delete_access_key(UserName=username, AccessKeyId=existing_access_keys[0]['AccessKeyId'])
        # request new access key and gather the response
        new_access_key = master_iam_client.create_access_key(UserName=username)
        current_dict['accesskey'] = new_access_key['AccessKey']['AccessKeyId']
        current_dict['secretkey'] = new_access_key['AccessKey']['SecretAccessKey']
        logging.info('applying new secret value to AWSPENDING')
        # save the new access key to the pending secret
        secretsmanager_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
    elif step == "testSecret":
        logging.debug("testSecret %s" % arn)
        # load the pending secret for testing
        pending_dict = get_secret_dict(secretsmanager_client, arn, "AWSPENDING", required_fields=['username'], token = token)
        # attempt to call an iam service using the credentials
        test_client = boto3.client('iam', aws_access_key_id=pending_dict['accesskey'], aws_secret_access_key=pending_dict['secretkey'])
        try:
            test_client.get_account_authorization_details()
        except test_client.exceptions.ClientError as e:
            # the test fails if and only if Authentication fails. Authorization failures are acceptable.
            if e.response['Error']['Code'] == 'AuthFailure':
                logging.error("Pending IAM secret %s in rotation %s failed the test to authenticate. exception: %s" % (arn, pending_dict['username'], repr(e)))
                raise ValueError("Pending IAM secret %s in rotation %s failed the test to authenticate. exception: %s" % (arn, pending_dict['username'], repr(e)))
    elif step == "finishSecret":
        logging.debug("finishSecret %s" % arn)
        # finalize the rotation process by marking the secret version passed in as the AWSCURRENT secret.
        metadata = secretsmanager_client.describe_secret(SecretId=arn)
        current_version = None
        for version in metadata["VersionIdsToStages"]:
            if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
                if version == token:
                    # The correct version is already marked as current, return
                    logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                    return
                current_version = version
                break
        # finalize by staging the secret version current
        secretsmanager_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
        logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))
    else:
        raise ValueError("Invalid step parameter")


def get_secret_dict(secretsmanager_client, arn, stage, required_fields=[], token=None):
    """
    Gets the secret dictionary corresponding for the secret arn, stage, and token
    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string
    Args:
        secretsmanager_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired
        stage (string): The stage identifying the secret version
    Returns:
        SecretDictionary: Secret dictionary
    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON
        KeyError: If the secret json does not contain the expected keys
    """
    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = secretsmanager_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = secretsmanager_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)
    # Run validations against the secret
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)
    # Parse and return the secret JSON string
    return secret_dict
