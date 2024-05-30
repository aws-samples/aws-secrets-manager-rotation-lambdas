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

TIMESTREAM_INFLUXDB_SERVICE = "timestream-influxdb"

# Mandatory user secret fields
INFLUXDB_ENGINE = "engine"
INFLUXDB_INSTANCE_IDENTIFIER = "dbIdentifier"

# Mandatory user secret fields
INFLUXDB_USERNAME = "username"

# Optional user secret fields
INFLUXDB_PASSWORD = "password"

# Optional token secret fields
INFLUXDB_TOKEN = "token"

# Stages
PREVIOUS_STAGE = "AWSPREVIOUS"
CURRENT_STAGE = "AWSCURRENT"
PENDING_STAGE = "AWSPENDING"

# Steps
CREATE_STEP = "createSecret"
SET_STEP = "setSecret"
TEST_STEP = "testSecret"
FINISH_STEP = "finishSecret"

# get_db_info response fields
INFLUXDB_ENDPOINT = "endpoint"

# Environment variable keys
SECRETS_MANAGER_ENDPOINT = "SECRETS_MANAGER_ENDPOINT"
AUTH_CREATION_ENABLED = "AUTHENTICATION_CREATION_ENABLED"


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
        'dbIdentifier': <optional: DB identifier>,
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
    version_id = event["ClientRequestToken"]
    step = event["Step"]

    if arn == "" or arn is None:
        raise ValueError("arn is null or empty.")
    if version_id == "" or version_id is None:
        raise ValueError("version_id is null or empty.")
    if step == "" or step is None:
        raise ValueError("step is null or empty.")

    boto_session = boto3.Session()

    if SECRETS_MANAGER_ENDPOINT not in os.environ:
        raise KeyError(
            "SECRETS_MANAGER_ENDPOINT environment variable not set in the environment variables."
        )

    secret_manager_endpoint = os.environ[SECRETS_MANAGER_ENDPOINT]
    if secret_manager_endpoint == "" or secret_manager_endpoint is None:
        raise ValueError(
            "Secret manager endpoint is null or empty, set the environment variable in the lambda configuration."
        )
    secrets_client = boto_session.client(
        "secretsmanager", endpoint_url=secret_manager_endpoint
    )

    # Make sure the version is staged correctly
    metadata = secrets_client.describe_secret(SecretId=arn)
    if not metadata["RotationEnabled"]:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata["VersionIdsToStages"]
    if version_id not in versions:
        logger.error(
            "Secret version %s has no stage for rotation of secret %s."
            % (version_id, arn)
        )
        raise ValueError(
            "Secret version %s has no stage for rotation of secret %s."
            % (version_id, arn)
        )
    if CURRENT_STAGE in versions[version_id]:
        logger.info(
            "Secret version %s already set as AWSCURRENT for secret %s."
            % (version_id, arn)
        )
        return
    elif PENDING_STAGE not in versions[version_id]:
        logger.error(
            "Secret version %s not set as AWSPENDING for rotation of secret %s."
            % (version_id, arn)
        )
        raise ValueError(
            "Secret version %s not set as AWSPENDING for rotation of secret %s."
            % (version_id, arn)
        )

    if step == CREATE_STEP:
        create_secret(secrets_client, boto_session, arn, version_id)

    elif step == SET_STEP:
        set_secret(secrets_client, boto_session, arn, version_id)

    elif step == TEST_STEP:
        test_secret(secrets_client, boto_session, arn, version_id)

    elif step == FINISH_STEP:
        finish_secret(secrets_client, boto_session, arn, version_id)

    else:
        raise ValueError("Invalid step parameter %s" % step)


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
        conn = influxdb_client.InfluxDBClient(
            url="https://" + endpoint_url + ":8086",
            username=secret_dict[INFLUXDB_USERNAME],
            password=secret_dict[INFLUXDB_PASSWORD],
            debug=False,
            verify_ssl=True,
        )

        # Verify InfluxDB connection
        health = conn.ping()
        if not health and not ignore_error:
            logger.error("%s: Connection failure" % step)

        yield conn
    except Exception as err:
        if not ignore_error:
            raise ValueError(
                "%s: Failed to set new authorization with secret ARN %s %s"
                % (step, arn, err)
            ) from err
    finally:
        if conn is not None:
            conn.close()


def create_secret(secrets_client, boto_session, arn, version_id):
    """Create the secret

    This method first checks for the existence of a secret for the passed in user. If one does not exist, it will generate a
    password and place a new secret in the pending stage.

    Args:
        secrets_client (client): The secrets manager service client
        boto_session (session): Session to retrieve timestream-influxdb client
        arn (string): The secret ARN or other identifier
        version_id (string): The ClientRequestToken associated with the secret version

    """

    # Make sure the current secret exists
    current_secret_dict = get_secret_dict(secrets_client, arn, CURRENT_STAGE)

    # Now try to get the secret, if that fails, put a new secret
    try:
        get_secret_dict(secrets_client, arn, PENDING_STAGE, version_id)
        logger.info("create_secret: Successfully retrieved secret for %s." % arn)
    except secrets_client.exceptions.ResourceNotFoundException:
        current_secret_dict[INFLUXDB_PASSWORD] = secrets_client.get_random_password()[
            "RandomPassword"
        ]
        secrets_client.put_secret_value(
            SecretId=arn,
            ClientRequestToken=version_id,
            SecretString=json.dumps(current_secret_dict),
            VersionStages=[PENDING_STAGE],
        )

    logger.info(
        "create_secret: Successfully created new authorization for ARN %s and version %s."
        % (arn, version_id)
    )


def set_secret(secrets_client, boto_session, arn, version_id):
    """Set the secret


    This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
    tries to login with the AWSCURRENT and AWSPREVIOUS secrets. If either one succeeds, it sets the AWSPENDING password
    as the user password in the database. Else, it throws a ValueError.

    Args:
        secrets_client (client): The secrets manager service client
        boto_session (session): Session to retrieve timestream-influxdb client
        arn (string): The secret ARN or other identifier
        version_id (string): The ClientRequestToken associated with the secret version

    """

    try:
        previous_secret_dict = get_secret_dict(secrets_client, arn, PREVIOUS_STAGE)
    except (secrets_client.exceptions.ResourceNotFoundException, KeyError):
        previous_secret_dict = None

    # Make sure the current secret exists
    current_secret_dict = get_secret_dict(secrets_client, arn, CURRENT_STAGE)
    pending_secret_dict = get_secret_dict(
        secrets_client, arn, PENDING_STAGE, version_id
    )
    endpoint_url = get_db_info(
        current_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER], boto_session
    )

    # Make sure the DB instance from current and pending match
    if (
        current_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER]
        != pending_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER]
    ):
        logger.error(
            "setSecret: Attempting to modify user for a DB %s other than current DB %s"
            % (
                pending_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER],
                current_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER],
            )
        )
        raise ValueError(
            "Attempting to modify user for DB %s other than current DB %s"
            % (
                pending_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER],
                current_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER],
            )
        )

    # Make sure the username in current and pending secrets match
    if current_secret_dict[INFLUXDB_USERNAME] != pending_secret_dict[INFLUXDB_USERNAME]:
        logger.error(
            "setSecret: Attempting to modify user %s other than current user %s"
            % (
                pending_secret_dict[INFLUXDB_USERNAME],
                current_secret_dict[INFLUXDB_USERNAME],
            )
        )
        raise ValueError(
            "Attempting to modify user for DB %s other than current DB %s"
            % (
                pending_secret_dict[INFLUXDB_USERNAME],
                current_secret_dict[INFLUXDB_USERNAME],
            )
        )

    # First try to login with the pending secret, if it succeeds, return
    try:
        with get_connection(
            endpoint_url, pending_secret_dict, arn, SET_STEP, True
        ) as pending_conn:
            pending_conn.organizations_api().find_organizations()
            logger.info("Successfully authenticated the pending user secret.")
            return
    except Exception:
        pass

    password_update_success = False
    # Attempt connection and password update with the current secret
    try:
        with get_connection(
            endpoint_url, current_secret_dict, arn, SET_STEP, True
        ) as conn:
            conn.users_api().update_password(
                user=conn.users_api().me().id,
                password=pending_secret_dict[INFLUXDB_PASSWORD],
            )
            password_update_success = True
    except Exception:
        pass

    # If the current secret fails to authenticate then we can attempt a connection with the previous secret
    if not password_update_success and previous_secret_dict is not None:
        try:
            with get_connection(
                endpoint_url, previous_secret_dict, arn, SET_STEP, True
            ) as conn:
                conn.users_api().update_password(
                    user=conn.users_api().me().id,
                    password=pending_secret_dict[INFLUXDB_PASSWORD],
                )
                password_update_success = True
        except Exception:
            pass

    if not password_update_success:
        raise ValueError(
            "Unable to log into database with previous, current, or pending secret of secret arn %s"
            % arn
        )

    logger.info(
        "set_secret: Successfully created new authorization for ARN %s and version %s."
        % (arn, version_id)
    )


def test_secret(secrets_client, boto_session, arn, version_id):
    """Test the user against the InfluxDB instance

    This method attempts a connection with the Timestream for InfluxDB instance with the secrets staged
    in AWSPENDING and ensures the pending and current secrets have matching dbIdentifier and username values.

    Args:
        secrets_client (client): The secrets manager service client
        boto_session (session): Session to retrieve timestream-influxdb client
        arn (string): The secret ARN or other identifier
        version_id (string): The ClientRequestToken associated with the secret version

    Raises: ValueError: If the secrets manager or pending users fail to authenticate.

    """

    current_secret_dict = get_secret_dict(secrets_client, arn, CURRENT_STAGE)
    pending_secret_dict = get_secret_dict(
        secrets_client, arn, PENDING_STAGE, version_id
    )

    # Verify that the current_secret_dict and pending_secret_dict share the same dbIdentifier
    if (
        current_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER]
        != pending_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER]
    ):
        raise ValueError(
            "Current and pending dbIdentifier values do not match for secret ARN %s"
            % arn
        )

    # Make sure the username  from current and pending match
    if current_secret_dict[INFLUXDB_USERNAME] != pending_secret_dict[INFLUXDB_USERNAME]:
        logger.error(
            "setSecret: Attempting to modify user %s other than current user %s"
            % (
                pending_secret_dict[INFLUXDB_USERNAME],
                current_secret_dict[INFLUXDB_USERNAME],
            )
        )
        raise ValueError(
            "Attempting to modify user for DB %s other than current DB %s"
            % (
                pending_secret_dict[INFLUXDB_USERNAME],
                current_secret_dict[INFLUXDB_USERNAME],
            )
        )

    # Verify pending authentication can successfully authenticate
    with get_connection(
        get_db_info(pending_secret_dict[INFLUXDB_INSTANCE_IDENTIFIER], boto_session),
        pending_secret_dict,
        arn,
        TEST_STEP,
    ) as pending_user_client:
        pending_user_client.organizations_api().find_organizations()

    logger.info("test_secret: Successfully tested authentication rotation")


def finish_secret(secrets_client, boto_session, arn, version_id):
    """Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        secrets_client (client): The secrets manager service client
        boto_session (session): Session to retrieve timestream-influxdb client
        arn (string): The secret ARN or other identifier
        version_id (string): The ClientRequestToken associated with the secret version

    Raises:
        ValueError: If the current secret and pending secret do not have matching dbIdentifier values.

    """

    # First describe the secret to get the current version
    metadata = secrets_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if CURRENT_STAGE in metadata["VersionIdsToStages"][version]:
            if version == version_id:
                # The correct version is already marked as current, return
                logger.info(
                    "finish_secret: Version %s already marked as AWSCURRENT for %s"
                    % (version, arn)
                )
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secrets_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage=CURRENT_STAGE,
        MoveToVersionId=version_id,
        RemoveFromVersionId=current_version,
    )

    logger.info(
        "finish_secret: Successfully set AWSCURRENT stage to version %s for secret %s."
        % (version_id, arn)
    )


def get_secret_dict(secrets_client, arn, stage, version_id=None):
    """Gets the secret dictionary corresponding for the secret arn, stage, and version_id

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

    # Only do VersionId validation against the stage if a version_id is passed in
    if version_id:
        secret = secrets_client.get_secret_value(
            SecretId=arn, VersionId=version_id, VersionStage=stage
        )
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
    required_fields = [
        INFLUXDB_ENGINE,
        INFLUXDB_USERNAME,
        INFLUXDB_PASSWORD,
        INFLUXDB_INSTANCE_IDENTIFIER,
    ]

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    if secret_dict["engine"] != TIMESTREAM_INFLUXDB_SERVICE:
        raise KeyError(
            "Database engine must be set to 'timestream-influxdb' in order to use this rotation lambda"
        )

    return secret_dict


def get_db_info(db_instance_identifier, boto_session):
    """Get InfluxDB information

    This helper function returns the url for the InfluxDB instance,
    that matches the identifier which is provided in the user secret.

    Args:
        db_instance_identifier (string): The InfluxDB instance identifier
        boto_session (session): Session to retrieve timestream-influxdb client

    Raises:
        ValueError: Failed to retrieve DB information
        KeyError: DB info returned does not contain expected key

    """

    influx_client = boto_session.client(TIMESTREAM_INFLUXDB_SERVICE)
    describe_response = influx_client.get_db_instance(identifier=db_instance_identifier)

    if describe_response is None or describe_response[INFLUXDB_ENDPOINT] is None:
        raise KeyError("Invalid endpoint info for influxdb instance")

    return describe_response[INFLUXDB_ENDPOINT]
