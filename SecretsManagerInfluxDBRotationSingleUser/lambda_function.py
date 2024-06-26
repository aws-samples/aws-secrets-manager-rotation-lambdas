# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import logging
import os
import influxdb_client
from contextlib import contextmanager

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """Secrets Manager InfluxDB User Rotation Multi User Handler

    This handler uses the single-user rotation scheme to rotate an InfluxDB authentication user. This rotation
    scheme authenticates the current user in the InfluxDB instance and creates a new password for the user.

    InfluxDB users do not hold a specific set of permissions, but rather own tokens. Tokens cannot be owned
    by multiple users. If the users who created a token gets deleted, so do the tokens. Tokens are the
    recommended way for managing access control with Timestream for InfluxDB. Users should be used to create
    tokens, and the single-user rotation lambda function should be used to manage password rotation for those users.

    The Secret SecretString is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'timestream-influxdb'>,
        'username': <required: username>,
        'password': <required: password>,
        'dbIdentifier': <required: DB identifier>,
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
        KeyError: If SECRETS_MANAGER_ENDPOINT not set in the environment variables

    """
    arn = event["SecretId"]
    version_token = event["ClientRequestToken"]
    step = event["Step"]

    boto_session = boto3.Session()
    secrets_client = boto_session.client("secretsmanager", endpoint_url=os.environ["SECRETS_MANAGER_ENDPOINT"])
    influxdb_client = boto_session.client("timestream-influxdb")

    # Make sure the version is staged correctly
    metadata = secrets_client.describe_secret(SecretId=arn)
    if "RotationEnabled" in metadata and not metadata["RotationEnabled"]:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata["VersionIdsToStages"]
    if version_token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (version_token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (version_token, arn))
    if "AWSCURRENT" in versions[version_token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (version_token, arn))
        return
    elif "AWSPENDING" not in versions[version_token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (version_token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (version_token, arn))

    if step == "createSecret":
        create_secret(secrets_client, arn, version_token)

    elif step == "setSecret":
        set_secret(secrets_client, influxdb_client, arn, version_token)

    elif step == "testSecret":
        test_secret(secrets_client, influxdb_client, arn, version_token)

    elif step == "finishSecret":
        finish_secret(secrets_client, arn, version_token)

    else:
        logger.error("lambda_handler: Invalid setp parameter %s for secret %s" % (step, arn))
        raise ValueError("Invalid step parameter %s for secret %s" % (step, arn))

def create_secret(secrets_client, arn, version_token):
    """Create the secret

    This method first checks for the existence of a secret for the passed in user. If one does not exist, it will generate a
    password and place a new secret in the pending stage.

    Args:
        secrets_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        version_token (string): The ClientRequestToken associated with the secret version

    """

    # Make sure the current secret exists
    current_secret_dict = get_secret_dict(secrets_client, arn, "AWSCURRENT")

    # Now try to get the secret, if that fails, put a new secret
    try:
        get_secret_dict(secrets_client, arn, "AWSPENDING", version_token)
        logger.info("create_secret: Successfully retrieved secret for %s." % arn)
    except secrets_client.exceptions.ResourceNotFoundException:
        current_secret_dict["password"] = secrets_client.get_random_password()["RandomPassword"]
        secrets_client.put_secret_value(SecretId=arn, ClientRequestToken=version_token, SecretString=json.dumps(current_secret_dict), VersionStages=["AWSPENDING"])

    logger.info("create_secret: Successfully generated new password and staged for ARN %s and version %s." % (arn, version_token))


def set_secret(secrets_client, influxdb_client, arn, version_token):
    """Set the secret


    This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
    tries to login with the AWSCURRENT and AWSPREVIOUS secrets. If either one succeeds, it sets the AWSPENDING password
    as the user password in the database. Else, it throws a ValueError.

    Args:
        secrets_client (client): The secrets manager service client
        influxdb_client (client): The InfluxDB client
        arn (string): The secret ARN or other identifier
        version_token (string): The ClientRequestToken associated with the secret version

    """

    try:
        previous_secret_dict = get_secret_dict(secrets_client, arn, "AWSPREVIOUS")
    except (secrets_client.exceptions.ResourceNotFoundException, KeyError):
        previous_secret_dict = None

    # Make sure the current secret exists
    current_secret_dict = get_secret_dict(secrets_client, arn, "AWSCURRENT")
    pending_secret_dict = get_secret_dict(secrets_client, arn, "AWSPENDING", version_token)
    endpoint_url = get_db_info(current_secret_dict["dbIdentifier"], influxdb_client)

    # Make sure the DB instance from current and pending match
    if current_secret_dict["dbIdentifier"] != pending_secret_dict["dbIdentifier"]:
        logger.error("setSecret: Attempting to modify user for a DB %s other than current DB %s" % (pending_secret_dict["dbIdentifier"], current_secret_dict["dbIdentifier"]))
        raise ValueError("Attempting to modify user for DB %s other than current DB %s" % (pending_secret_dict["dbIdentifier"], current_secret_dict["dbIdentifier"]))

    # Make sure the username in current and pending secrets match
    if current_secret_dict["username"] != pending_secret_dict["username"]:
        logger.error("setSecret: Attempting to modify user %s other than current user %s" % (pending_secret_dict["username"], current_secret_dict["username"]))
        raise ValueError("Attempting to modify user for DB %s other than current DB %s" % (pending_secret_dict["username"], current_secret_dict["username"]))

    # First try to login with the pending secret, if it succeeds, return
    try:
        with get_connection(endpoint_url, pending_secret_dict, arn, "setSecret", True) as pending_conn:
            pending_conn.organizations_api().find_organizations()
            logger.info("Successfully authenticated the pending user secret.")
            return
    except Exception:
        pass

    password_update_success = False
    # Attempt connection and password update with the current secret
    try:
        with get_connection(endpoint_url, current_secret_dict, arn, "setSecret", True) as conn:
            conn.users_api().update_password(user=conn.users_api().me().id, password=pending_secret_dict["password"])
            password_update_success = True
            logger.info("Successfully authenticated the current secret for updating password")
    except Exception:
        pass

    # If the current secret fails to authenticate then we can attempt a connection with the previous secret
    if not password_update_success and previous_secret_dict is not None:
        try:
            with get_connection(endpoint_url, previous_secret_dict, arn, "setSecret", True) as conn:
                conn.users_api().update_password(user=conn.users_api().me().id, password=pending_secret_dict["password"])
                logger.info("Successfully authenticated the previous secret for updating password")
                password_update_success = True
        except Exception:
            pass

    if not password_update_success:
        logger.error("setSecret: Failed to update password for secret arn %s" % arn)
        raise ValueError("Unable to log into database with previous, current, or pending secret of secret arn %s" % arn)

    logger.info("set_secret: Successfully updated the password for ARN %s and version %s." % (arn, version_token))


def test_secret(secrets_client, influxdb_client, arn, version_token):
    """Test the user against the InfluxDB instance

    This method attempts a connection with the Timestream for InfluxDB instance with the secrets staged
    in AWSPENDING and ensures the pending and current secrets have matching dbIdentifier and username values.

    Args:
        secrets_client (client): The secrets manager service client
        influxdb_client (client): The InfluxDB client
        arn (string): The secret ARN or other identifier
        version_token (string): The ClientRequestToken associated with the secret version

    Raises: ValueError: If the secrets manager or pending users fail to authenticate.

    """

    pending_secret_dict = get_secret_dict(secrets_client, arn, "AWSPENDING", version_token)

    # Verify pending authentication can successfully authenticate
    with get_connection(get_db_info(pending_secret_dict["dbIdentifier"], influxdb_client), pending_secret_dict, arn, "testSecret") as pending_user_client:
        pending_user_client.organizations_api().find_organizations()

    logger.info("test_secret: Successfully tested authentication rotation")


def finish_secret(secrets_client, arn, version_token):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        secrets_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        version_token (string): The ClientRequestToken associated with the secret version

    Raises:
        ValueError: If the current secret and pending secret do not have matching dbIdentifier values.

    """

    # First describe the secret to get the current version
    metadata = secrets_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == version_token:
                # The correct version is already marked as current, return
                logger.info("finish_secret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secrets_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=version_token, RemoveFromVersionId=current_version,)

    logger.info("finish_secret: Successfully set AWSCURRENT stage to version %s for secret %s." % (version_token, arn))


def get_secret_dict(secrets_client, arn, stage, version_token=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and version_token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the
    JSON string

    Args:
        secrets_client (client): The secrets manager service client
        arn (string): The secret ARN or other identifier
        stage (string): The stage identifying the secret version
        versionId (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
        ValueError: If the secret is not valid JSON
        KeyError: If required keys missing in secret or engine is not 'timestream-influxdb'

    """

    # Only do VersionId validation against the stage if a version_token is passed in
    if version_token:
        secret = secrets_client.get_secret_value(SecretId=arn, VersionId=version_token, VersionStage=stage)
    else:
        secret = secrets_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret["SecretString"]
    try:
        secret_dict = json.loads(plaintext)
    except Exception:
        # wrapping json parser exceptions to avoid possible token disclosure
        logger.error("Invalid secret value json for secret %s." % arn)
        raise ValueError("Invalid secret value json for secret %s." % arn)

    # Run semantic validations for secrets
    required_fields = ["engine", "username", "password", "dbIdentifier"]

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    if secret_dict["engine"] != "timestream-influxdb":
        raise KeyError("Database engine must be set to 'timestream-influxdb' in order to use this rotation lambda")

    return secret_dict


def get_db_info(db_instance_identifier, influxdb_client):
    """Get InfluxDB information

    This helper function returns the url for the InfluxDB instance,
    that matches the identifier which is provided in the user secret.

    Args:
        db_instance_identifier (string): The InfluxDB instance identifier
        influxdb_client (client): The InfluxDB client

    Returns:
        endpoint (string): The endpoint for the DB instance

    Raises:
        ValueError: Failed to retrieve DB information
        KeyError: DB info returned does not contain expected key

    """

    describe_response = influxdb_client.get_db_instance(identifier=db_instance_identifier)

    if describe_response is None or describe_response["endpoint"] is None:
        raise KeyError("Invalid endpoint info for influxdb instance")

    return describe_response["endpoint"]



@contextmanager
def get_connection(endpoint_url, secret_dict, arn, step, ignore_error=False):
    """Get connection to InfluxDB

    This helper function returns a connection to the provided InfluxDB instance.

    Args:
        endpoint_url (string): Url for the InfluxDB instance
        secret_dict (dictionary): Dictionary with username/password to authenticate connection
        arn (string): Arn for secret to log in event of failure to make connection
        step (string): Step in which the lambda function is making the connection
        ignore_error (boolean): Flag for if to ignore errors

    Raises:
        ValueError: If the connection or health check fails

    """
    conn = None
    try:
        conn = influxdb_client.InfluxDBClient(url="https://" + endpoint_url + ":8086", username=secret_dict["username"], password=secret_dict["password"], debug=False, verify_ssl=True)

        # Verify InfluxDB connection
        health = conn.ping()
        if not health and not ignore_error:
            logger.error("%s: Connection failure" % step)

        yield conn
    except Exception as err:
        if not ignore_error:
            logger.error("%s: Connection failure with secret ARN %s %s" % (step, arn, err))
            raise ValueError("%s: Failed to set new authorization with secret ARN %s %s" % (step, arn, err)) from err
    finally:
        if conn is not None:
            conn.close()



