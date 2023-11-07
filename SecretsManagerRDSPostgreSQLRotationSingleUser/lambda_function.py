# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
import boto3
import json
import logging
import os
import pg
import pgdb

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_RDS_DB_INSTANCE_ARN_LENGTH = 256

def lambda_handler(event, context):
    """Secrets Manager RDS PostgreSQL Handler

    This handler uses the single-user rotation scheme to rotate an RDS PostgreSQL user credential. This rotation
    scheme logs into the database as the user and rotates the user's own password, immediately invalidating the
    user's previous password.

    The Secret SecretString is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'postgres'>,
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name, default to 'postgres'>,
        'port': <optional: if not specified, default port 5432 will be used>
        'masterarn': <required: the arn of the master secret which will be used to create user>
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

        KeyError: If the secret json does not contain the expected keys

    """
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    logger.info("event (s) %s", event)
    logger.info("event (r) %r", event)
    logger.info("context (s) %s", context)
    logger.info("context (r) %r", context)

    # Setup the client
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
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
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        logger.error("lambda_handler: Invalid step parameter %s for secret %s" % (step, arn))
        raise ValueError("Invalid step parameter %s for secret %s" % (step, arn))


def create_secret(service_client, arn, token):
    """Generate a new secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ValueError: If the current secret is not valid JSON

        KeyError: If the secret json does not contain the expected keys

    """
    # Make sure the current secret exists
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        get_secret_dict(service_client, arn, "AWSPENDING", token)
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Get exclude characters from environment variable
        exclude_characters = os.environ['EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else ':/@"\'\\'
        # Generate a random password
        passwd = service_client.get_random_password(ExcludeCharacters=exclude_characters)
        current_dict['password'] = passwd['RandomPassword']

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):
    """Set the pending secret in the database

    This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
    tries to login with the AWSCURRENT and AWSPREVIOUS secrets. If either one succeeds, it sets the AWSPENDING password
    as the user password in the database. Else, it throws a ValueError.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or valid credentials are found to login to the database

        KeyError: If the secret json does not contain the expected keys

    """
    try:
        previous_dict = get_secret_dict(service_client, arn, "AWSPREVIOUS")
    except (service_client.exceptions.ResourceNotFoundException, KeyError):
        previous_dict = None
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)

    create_user_if_not_exists(service_client, current_dict, pending_dict)

    # First try to login with the pending secret, if it succeeds, return
    conn = get_connection(pending_dict)
    if conn:
        conn.close()
        logger.info("setSecret: AWSPENDING secret is already set as password in PostgreSQL DB for secret arn %s." % arn)
        return

    # Make sure the user from current and pending match
    if current_dict['username'] != pending_dict['username']:
        logger.error("setSecret: Attempting to modify user %s other than current user %s" % (pending_dict['username'], current_dict['username']))
        raise ValueError("Attempting to modify user %s other than current user %s" % (pending_dict['username'], current_dict['username']))

    # Make sure the host from current and pending match
    if current_dict['host'] != pending_dict['host']:
        logger.error("setSecret: Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))
        raise ValueError("Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))

    # Now try the current password
    conn = get_connection(current_dict)

    # If both current and pending do not work, try previous
    if not conn and previous_dict:
        # Update previous_dict to leverage current SSL settings
        previous_dict.pop('ssl', None)
        if 'ssl' in current_dict:
            previous_dict['ssl'] = current_dict['ssl']

        conn = get_connection(previous_dict)

        # Make sure the user/host from previous and pending match
        if previous_dict['username'] != pending_dict['username']:
            logger.error("setSecret: Attempting to modify user %s other than previous valid user %s" % (pending_dict['username'], previous_dict['username']))
            raise ValueError("Attempting to modify user %s other than previous valid user %s" % (pending_dict['username'], previous_dict['username']))
        if previous_dict['host'] != pending_dict['host']:
            logger.error("setSecret: Attempting to modify user for host %s other than previous valid host %s" % (pending_dict['host'], previous_dict['host']))
            raise ValueError("Attempting to modify user for host %s other than current previous valid %s" % (pending_dict['host'], previous_dict['host']))

    # If we still don't have a connection, raise a ValueError
    if not conn:
        logger.error("setSecret: Unable to log into database with previous, current, or pending secret of secret arn %s" % arn)
        raise ValueError("Unable to log into database with previous, current, or pending secret of secret arn %s" % arn)

    # Now set the password to the pending password
    try:
        with conn.cursor() as cur:
            # Get escaped username via quote_ident
            cur.execute("SELECT quote_ident(%s)", (pending_dict['username'],))
            escaped_username = cur.fetchone()[0]

            alter_role = "ALTER USER %s" % escaped_username
            cur.execute(alter_role + " WITH PASSWORD %s", (pending_dict['password'],))
            conn.commit()
            logger.info("setSecret: Successfully set password for user %s in PostgreSQL DB for secret arn %s." % (pending_dict['username'], arn))
    finally:
        conn.close()


def test_secret(service_client, arn, token):
    """Test the pending secret against the database

    This method tries to log into the database with the secrets staged with AWSPENDING and runs
    a permissions check to ensure the user has the corrrect permissions.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or valid credentials are found to login to the database

        KeyError: If the secret json does not contain the expected keys

    """
    # Try to login with the pending secret, if it succeeds, return
    conn = get_connection(get_secret_dict(service_client, arn, "AWSPENDING", token))
    if conn:
        # This is where the lambda will validate the user's permissions. Uncomment/modify the below lines to
        # tailor these validations to your needs
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT NOW()")
                conn.commit()
        finally:
            conn.close()

        logger.info("testSecret: Successfully signed into PostgreSQL DB with AWSPENDING secret in %s." % arn)
        return
    else:
        logger.error("testSecret: Unable to log into database with pending secret of secret ARN %s" % arn)
        raise ValueError("Unable to log into database with pending secret of secret ARN %s" % arn)


def finish_secret(service_client, arn, token):
    """Finish the rotation by marking the pending secret as current

    This method finishes the secret rotation by staging the secret staged AWSPENDING with the AWSCURRENT stage.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
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
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


def get_connection(secret_dict):
    """Gets a connection to PostgreSQL DB from a secret dictionary

    This helper function uses connectivity information from the secret dictionary to initiate
    connection attempt(s) to the database. Will attempt a fallback, non-SSL connection when
    initial connection fails using SSL and fall_back is True.

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Connection: The pgdb.Connection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Parse and validate the secret JSON string
    port = int(secret_dict['port']) if 'port' in secret_dict else 5432
    dbname = secret_dict['dbname'] if 'dbname' in secret_dict else "postgres"

    # Get SSL connectivity configuration
    use_ssl, fall_back = get_ssl_config(secret_dict)

    # if an 'ssl' key is not found or does not contain a valid value, attempt an SSL connection and fall back to non-SSL on failure
    conn = connect_and_authenticate(secret_dict, port, dbname, use_ssl)
    logger.info("(use_ssl) conn %r" % conn)
    if conn or not fall_back:
        return conn
    else:
        logger.info("falling back to connect_and_authenticate")
        return connect_and_authenticate(secret_dict, port, dbname, False)


def get_ssl_config(secret_dict):
    """Gets the desired SSL and fall back behavior using a secret dictionary

    This helper function uses the existance and value the 'ssl' key in a secret dictionary
    to determine desired SSL connectivity configuration. Its behavior is as follows:
        - 'ssl' key DNE or invalid type/value: return True, True
        - 'ssl' key is bool: return secret_dict['ssl'], False
        - 'ssl' key equals "true" ignoring case: return True, False
        - 'ssl' key equals "false" ignoring case: return False, False

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Tuple(use_ssl, fall_back): SSL configuration
            - use_ssl (bool): Flag indicating if an SSL connection should be attempted
            - fall_back (bool): Flag indicating if non-SSL connection should be attempted if SSL connection fails

    """
    # Default to True for SSL and fall_back mode if 'ssl' key DNE
    if 'ssl' not in secret_dict:
        return True, True

    # Handle type bool
    if isinstance(secret_dict['ssl'], bool):
        return secret_dict['ssl'], False

    # Handle type string
    if isinstance(secret_dict['ssl'], str):
        ssl = secret_dict['ssl'].lower()
        if ssl == "true":
            return True, False
        elif ssl == "false":
            return False, False
        else:
            # Invalid string value, default to True for both SSL and fall_back mode
            return True, True

    # Invalid type, default to True for both SSL and fall_back mode
    return True, True


def connect_and_authenticate(secret_dict, port, dbname, use_ssl):
    """Attempt to connect and authenticate to a PostgreSQL instance

    This helper function tries to connect to the database using connectivity info passed in.
    If successful, it returns the connection, else None

    Args:
        - secret_dict (dict): The Secret Dictionary
        - port (int): The databse port to connect to
        - dbname (str): Name of the database
        - use_ssl (bool): Flag indicating whether connection should use SSL/TLS

    Returns:
        Connection: The pymongo.database.Database object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Try to obtain a connection to the db
    if use_ssl:
        try:
            # Setting sslmode='verify-full' will verify the server's certificate and check the server's host name
            conn = pgdb.connect(host=secret_dict['host'], user=secret_dict['username'], password=secret_dict['password'], database=dbname, port=port,
                                connect_timeout=5, sslrootcert='/etc/pki/tls/cert.pem', sslmode='verify-full')
            return conn
        except Exception as e:
            logger.error("ssl connection connection failed with error: %r" % e)
            return connect_and_authenticate(secret_dict, port, dbname, False)

    try:
        conn = pgdb.connect(host=secret_dict['host'], user=secret_dict['username'], password=secret_dict['password'], database=dbname, port=port,
                        connect_timeout=5, sslmode='disable')
        logger.info("Successfully established %s connection as user '%s' with host: '%s'" % ("SSL/TLS" if use_ssl else "non SSL/TLS", secret_dict['username'], secret_dict['host']))
        return conn
    except pg.InternalError as e:
        if "server does not support SSL, but SSL was required" in e.args[0]:
            logger.error("Unable to establish SSL/TLS handshake, SSL/TLS is not enabled on the host: %s" % secret_dict['host'])
        elif re.search('server common name ".+" does not match host name ".+"', e.args[0]):
            logger.error("Hostname verification failed when estlablishing SSL/TLS Handshake with host: %s" % secret_dict['host'])
        elif re.search('no pg_hba.conf entry for host ".+", SSL off', e.args[0]):
            logger.error("Unable to establish SSL/TLS handshake, SSL/TLS is enforced on the host: %s" % secret_dict['host'])
        else:
            logger.error("pg.InternalError: %r" % e)
        return None


def get_secret_dict(service_client, arn, stage, token=None, master_secret=False):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        stage (string): The stage identifying the secret version

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        master_secret (boolean): A flag that indicates if we are getting a master secret.

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON

        KeyError: If the secret json does not contain the expected keys

    """
    required_fields = ['host', 'username', 'password', 'engine']

    # Only do VersionId validation against the stage if a token is passed in
    if token:
        secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage=stage)
    else:
        secret = service_client.get_secret_value(SecretId=arn, VersionStage=stage)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    # Run validations against the secret
    if master_secret and (set(secret_dict.keys()) == set(['username', 'password'])):
        # If this is an RDS-made Master Secret, we can fetch `host` and other connection params
        # from the DescribeDBInstances/DescribeDBClusters RDS API using the DB Instance/Cluster ARN as a filter.
        # The DB Instance/Cluster ARN is fetched from the RDS-made Master Secret's System Tags.
        db_instance_arn = fetch_instance_arn_from_system_tags(service_client, arn)
        if db_instance_arn is not None:
            secret_dict = get_connection_params_from_rds_api(secret_dict, db_instance_arn)
            logger.info("setSecret: Successfully fetched connection params for Master Secret %s from DescribeDBInstances API." % arn)

        # For non-RDS-made Master Secrets that are missing `host`, this will error below when checking for required connection params.

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    supported_engines = ["postgres", "aurora-postgresql"]
    if secret_dict['engine'] not in supported_engines:
        raise KeyError("Database engine must be set to 'postgres' in order to use this rotation lambda")

    # Parse and return the secret JSON string
    return secret_dict

def is_rds_replica_database(replica_dict, master_dict):
    """Validates that the database of a secret is a replica of the database of the master secret

    This helper function validates that the database of a secret is a replica of the database of the master secret.

    Args:
        replica_dict (dictionary): The secret dictionary containing the replica database

        primary_dict (dictionary): The secret dictionary containing the primary database

    Returns:
        isReplica : whether or not the database is a replica

    Raises:
        ValueError: If the new username length would exceed the maximum allowed
    """
    # Setup the client
    rds_client = boto3.client('rds')

    # Get instance identifiers from endpoints
    replica_instance_id = replica_dict['host'].split(".")[0]
    master_instance_id = master_dict['host'].split(".")[0]

    try:
        describe_response = rds_client.describe_db_instances(DBInstanceIdentifier=replica_instance_id)
    except Exception as err:
        logger.warning("Encountered error while verifying rds replica status: %s" % err)
        return False
    instances = describe_response['DBInstances']

    # Host from current secret cannot be found
    if not instances:
        logger.info("Cannot verify replica status - no RDS instance found with identifier: %s" % replica_instance_id)
        return False

    # DB Instance identifiers are unique - can only be one result
    current_instance = instances[0]
    return master_instance_id == current_instance.get('ReadReplicaSourceDBInstanceIdentifier')

def fetch_instance_arn_from_system_tags(service_client, secret_arn):
    """Fetches DB Instance/Cluster ARN from the given secret's metadata.

    Fetches DB Instance/Cluster ARN from the given secret's metadata.

    Args:
        service_client (client): The secrets manager service client

        secret_arn (String): The secret ARN used in a DescribeSecrets API call to fetch the secret's metadata.

    Returns:
        db_instance_arn (String): The DB Instance/Cluster ARN of the Primary RDS Instance

    """

    metadata = service_client.describe_secret(SecretId=secret_arn)

    if 'Tags' not in metadata:
        logger.warning("setSecret: The secret %s is not a service-linked secret, so it does not have a tag aws:rds:primarydbinstancearn or a tag aws:rds:primarydbclusterarn" % secret_arn)
        return None

    tags = metadata['Tags']

    # Check if DB Instance/Cluster ARN is present in secret Tags
    global ARN_SYSTEM_TAG
    db_instance_arn = None
    for tag in tags:
        if tag['Key'].lower() == 'aws:rds:primarydbinstancearn' or tag['Key'].lower() == 'aws:rds:primarydbclusterarn':
            ARN_SYSTEM_TAG = tag['Key'].lower()
            db_instance_arn = tag['Value']

    # DB Instance/Cluster ARN must be present in secret System Tags to use this work-around
    if db_instance_arn is None:
        logger.warning("setSecret: DB Instance ARN not present in Metadata System Tags for secret %s" % secret_arn)
    elif len(db_instance_arn) > MAX_RDS_DB_INSTANCE_ARN_LENGTH:
        logger.error("setSecret: %s is not a valid DB Instance ARN. It exceeds the maximum length of %d." % (db_instance_arn, MAX_RDS_DB_INSTANCE_ARN_LENGTH))
        raise ValueError("%s is not a valid DB Instance ARN. It exceeds the maximum length of %d." % (db_instance_arn, MAX_RDS_DB_INSTANCE_ARN_LENGTH))

    return db_instance_arn


def get_connection_params_from_rds_api(master_dict, master_instance_arn):
    """Fetches connection parameters (`host`, `port`, etc.) from the DescribeDBInstances/DescribeDBClusters RDS API using `master_instance_arn` in the master secret metadata as a filter.

    This helper function fetches connection parameters from the DescribeDBInstances/DescribeDBClusters RDS API using `master_instance_arn` in the master secret metadata as a filter.

    Args:
        master_dict (dictionary): The master secret dictionary that will be updated with connection parameters.

        master_instance_arn (string): The DB Instance/Cluster ARN from master secret System Tags that will be used as a filter in DescribeDBInstances/DescribeDBClusters RDS API calls.

    Returns:
        master_dict (dictionary): An updated master secret dictionary that now contains connection parameters such as `host`, `port`, etc.

    Raises:
        Exception: If there is some error/throttling when calling the DescribeDBInstances/DescribeDBClusters RDS API

        ValueError: If the DescribeDBInstances/DescribeDBClusters RDS API Response contains no Instances
    """
    # Setup the client
    rds_client = boto3.client('rds')

    if ARN_SYSTEM_TAG == 'aws:rds:primarydbinstancearn':
        # Call DescribeDBInstances RDS API
        try:
            describe_response = rds_client.describe_db_instances(DBInstanceIdentifier=master_instance_arn)
        except Exception as err:
            logger.error("setSecret: Encountered API error while fetching connection parameters from DescribeDBInstances RDS API: %s" % err)
            raise Exception("Encountered API error while fetching connection parameters from DescribeDBInstances RDS API: %s" % err)
        # Verify the instance was found
        instances = describe_response['DBInstances']
        if len(instances) == 0:
            logger.error("setSecret: %s is not a valid DB Instance ARN. No Instances found when using DescribeDBInstances RDS API to get connection params." % master_instance_arn)
            raise ValueError("%s is not a valid DB Instance ARN. No Instances found when using DescribeDBInstances RDS API to get connection params." % master_instance_arn)

        # put connection parameters in master secret dictionary
        primary_instance = instances[0]
        master_dict['host'] = primary_instance['Endpoint']['Address']
        master_dict['port'] = primary_instance['Endpoint']['Port']
        master_dict['engine'] = primary_instance['Engine']

    elif ARN_SYSTEM_TAG == 'aws:rds:primarydbclusterarn':
        # Call DescribeDBClusters RDS API
        try:
            describe_response = rds_client.describe_db_clusters(DBClusterIdentifier=master_instance_arn)
        except Exception as err:
            logger.error("setSecret: Encountered API error while fetching connection parameters from DescribeDBClusters RDS API: %s" % err)
            raise Exception("Encountered API error while fetching connection parameters from DescribeDBClusters RDS API: %s" % err)
        # Verify the instance was found
        instances = describe_response['DBClusters']
        if len(instances) == 0:
            logger.error("setSecret: %s is not a valid DB Cluster ARN. No Instances found when using DescribeDBClusters RDS API to get connection params." % master_instance_arn)
            raise ValueError("%s is not a valid DB Cluster ARN. No Instances found when using DescribeDBClusters RDS API to get connection params." % master_instance_arn)

        # put connection parameters in master secret dictionary
        primary_instance = instances[0]
        master_dict['host'] = primary_instance['Endpoint']
        master_dict['port'] = primary_instance['Port']
        master_dict['engine'] = primary_instance['Engine']

    return master_dict

def create_user_if_not_exists(service_client, current_dict, pending_dict):
    """Creates the user if masterarn is supplied and the user does not exist in database.

    This function creates the user if masterarn is supplied and the user does not exist in database.

    Args:
        service_client (client): The secrets manager service client

        current_dict (dictionary): The current secret dictionary

        pending_dict (dictionary): The pending secret dictionary

    Returns:
        wasCreated (bool) : whether or not the database user was created

    Raises:
        ValueError: If the new username length would exceed the maximum allowed
    """
    user_created = False

    # If masterarn has been given, check if the user exists and create if not.
    if current_dict.get('masterarn'):
        # Use the master arn from the current secret to fetch master secret contents
        master_arn = current_dict['masterarn']
        master_dict = get_secret_dict(service_client, master_arn, "AWSCURRENT", None, True)

        # Fetch dbname from the Child User
        master_dict['dbname'] = current_dict.get('dbname', None)

        if current_dict['host'] != master_dict['host'] and not is_rds_replica_database(current_dict, master_dict):
            # If current dict is a replica of the master dict, can proceed
            logger.error("create_user_if_not_exists: Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))
            raise ValueError("Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))

        # Now log into the database with the master credentials
        conn = get_connection(master_dict)
        if not conn:
            logger.error("create_user_if_not_exists: Unable to log into database using credentials in master secret %s" % master_arn)
            raise ValueError("Unable to log into database using credentials in master secret %s" % master_arn)

        try:
            with conn.cursor() as cur:
                # Get escaped username via quote_ident
                cur.execute("SELECT quote_ident(%s)", (current_dict['username'],))
                current_username = cur.fetchone()[0]

                # Check if the user exists, if not create it and grant connect to the database
                # This default permission can be revoked or modified after the user has been created.
                cur.execute("SELECT 1 FROM pg_roles where rolname = %s", (current_dict['username'],))
                if len(cur.fetchall()) == 0:
                    cur.execute("CREATE ROLE %s WITH LOGIN PASSWORD %s", (current_username, current_dict['password'],))
                    cur.execute("GRANT CONNECT ON DATABASE %s TO %s" % (current_dict['dbname'], current_username))
                    user_created = True

                conn.commit()
                logger.info("create_user_if_not_exists: Successfully created user %s in PostgreSQL DB %s." % (current_username, current_dict['dbname']))
        finally:
            conn.close()

    return user_created