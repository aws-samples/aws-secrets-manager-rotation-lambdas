# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re
import boto3
import json
import logging
import os
from pymongo import MongoClient, errors

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_RDS_DB_INSTANCE_ARN_LENGTH = 256


def lambda_handler(event, context):
    """Secrets Manager MongoDB Handler

    This handler uses the master-user rotation scheme to rotate an MongoDB user credential. During the first rotation, this
    scheme logs into the database as the master user, creates a new user (appending _clone to the username), and grants the
    new user all of the permissions from the user being rotated. Once the secret is in this state, every subsequent rotation
    simply creates a new secret with the AWSPREVIOUS user credentials, changes that user's password, and then marks the
    latest secret as AWSCURRENT.

    The Secret SecretString is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'mongo'>,
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name>,
        'port': <optional: if not specified, default port 27017 will be used>,
        'masterarn': <required: the arn of the master secret which will be used to create users/change passwords>
        'ssl': <optional: if not specified, defaults to false. This must be true if being used for DocumentDB rotations where the cluster has TLS enabled>
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
    new secret and save it using the passed in token.

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
        # Get the alternate username swapping between the original user and the user with _clone appended to it
        current_dict['username'] = get_alt_username(current_dict['username'])
        # Generate a random password
        current_dict['password'] = get_random_password(service_client)

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):
    """Set the pending secret in the database

    This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
    tries to login with the master credentials from the masterarn in the current secret. If this succeeds, it adds all
    grants for AWSCURRENT user to the AWSPENDING user, creating the user and/or setting the password in the process.
    Else, it throws a ValueError.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or master credentials could not be used to login to DB

        KeyError: If the secret json does not contain the expected keys

    """
    # First try to login with the pending secret, if it succeeds, return
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)
    conn = get_connection(pending_dict)
    if conn:
        conn.logout()
        logger.info("setSecret: AWSPENDING secret is already set as password in MongoDB for secret arn %s." % arn)
        return

    # Make sure the user from current and pending match
    if get_alt_username(current_dict['username']) != pending_dict['username']:
        logger.error("setSecret: Attempting to modify user %s other than current user or clone %s" % (pending_dict['username'], current_dict['username']))
        raise ValueError("Attempting to modify user %s other than current user or clone %s" % (pending_dict['username'], current_dict['username']))

    # Make sure the host from current and pending match
    if current_dict['host'] != pending_dict['host']:
        logger.error("setSecret: Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))
        raise ValueError("Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))

    # Before we do anything with the secret, make sure the AWSCURRENT secret is valid by logging in to the db
    # This ensures that the credential we are rotating is valid to protect against a confused deputy attack
    conn = get_connection(current_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using current credentials for secret %s" % arn)
        raise ValueError("Unable to log into database using current credentials for secret %s" % arn)
    conn.logout()

    # Now get the master arn from the current secret to fetch master secret contents
    master_arn = current_dict['masterarn']
    master_dict = get_secret_dict(service_client, master_arn, "AWSCURRENT", None, True)
    if current_dict['host'] != master_dict['host']:
        logger.error("setSecret: Current database host %s is not the same host as master %s" % (current_dict['host'], master_dict['host']))
        raise ValueError("Current database host %s is not the same host as master %s" % (current_dict['host'], master_dict['host']))

    # Now log into the database with the master credentials
    conn = get_connection(master_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using credentials in master secret %s" % master_arn)
        raise ValueError("Unable to log into database using credentials in master secret %s" % master_arn)

    # Now set the password to the pending password
    try:
        user_info = conn.command('usersInfo', pending_dict['username'])
        if user_info['users']:
            conn.command("updateUser", pending_dict['username'], pwd=pending_dict['password'])
        else:
            user_info = conn.command('usersInfo', current_dict['username'])
            conn.command("createUser", pending_dict['username'], pwd=pending_dict['password'], roles=user_info['users'][0]['roles'])
        logger.info("setSecret: Successfully set password for %s in MongoDB for secret arn %s." % (pending_dict['username'], arn))
    except errors.PyMongoError:
        logger.error("setSecret: Error encountered when attempting to set password in database for user %s", pending_dict['username'])
        raise ValueError("Error encountered when attempting to set password in database for user %s", pending_dict['username'])
    finally:
        conn.logout()


def test_secret(service_client, arn, token):
    """Test the pending secret against the database

    This method tries to log into the database with the secrets staged with AWSPENDING and runs
    a permissions check to ensure the user has the correct permissions.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or pending credentials could not be used to login to the database

        KeyError: If the secret json does not contain the expected keys

    """
    # Try to login with the pending secret, if it succeeds, return
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)
    conn = get_connection(pending_dict)
    if conn:
        # This is where the lambda will validate the user's permissions. Modify the below lines to
        # tailor these validations to your needs
        try:
            conn.command('usersInfo', pending_dict['username'])
        finally:
            conn.logout()

        logger.info("testSecret: Successfully signed into MongoDB with AWSPENDING secret in %s." % arn)
        return
    else:
        logger.error("testSecret: Unable to log into database with pending secret of secret ARN %s" % arn)
        raise ValueError("Unable to log into database with pending secret of secret ARN %s" % arn)


def finish_secret(service_client, arn, token):
    """Finish the rotation by marking the pending secret as current

    This method moves the secret from the AWSPENDING stage to the AWSCURRENT stage.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

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
    """Gets a connection to MongoDB from a secret dictionary

    This helper function uses connectivity information from the secret dictionary to initiate
    connection attempt(s) to the database. Will attempt a fallback, non-SSL connection when
    initial connection fails using SSL and fall_back is True.

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Connection: The pymongo.database.Database object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Parse and validate the secret JSON string
    port = int(secret_dict['port']) if 'port' in secret_dict else 27017
    dbname = secret_dict['dbname'] if 'dbname' in secret_dict else "admin"

    # Get SSL connectivity configuration
    use_ssl, fall_back = get_ssl_config(secret_dict)

    # if an 'ssl' key is not found or does not contain a valid value, attempt an SSL connection and fall back to non-SSL on failure
    conn = connect_and_authenticate(secret_dict, port, dbname, use_ssl)
    if conn or not fall_back:
        return conn
    else:
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
    """Attempt to connect and authenticate to a MongoDB instance

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
    try:
        # Hostname verfification and server certificate validation enabled by default when ssl=True
        client = MongoClient(host=secret_dict['host'], port=port, connectTimeoutMS=5000, serverSelectionTimeoutMS=5000, ssl=use_ssl)
        db = client[dbname]
        db.authenticate(secret_dict['username'], secret_dict['password'])
        logger.info("Successfully established %s connection as user '%s' with host: '%s'" % ("SSL/TLS" if use_ssl else "non SSL/TLS", secret_dict['username'], secret_dict['host']))
        return db
    except errors.PyMongoError as e:
        if 'SSL handshake failed' in e.args[0]:
            logger.error("Unable to establish SSL/TLS handshake, check that SSL/TLS is enabled on the host: %s" % secret_dict['host'])
        elif re.search("hostname '.+' doesn't match", e.args[0]):
            logger.error("Hostname verification failed when estlablishing SSL/TLS Handshake with host: %s" % secret_dict['host'])
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
        # If this is an DocumentDB-made Master Secret, we can fetch `host` and other connection params
        # from the DescribeDBClusters DocDB API using the DB Cluster ARN as a filter.
        # The DB Cluster ARN is fetched from the DocumentDB-made Master Secret's AWS generated tags.
        db_cluster_arn = fetch_cluster_arn_from_tags(service_client, arn)
        if db_cluster_arn:
            secret_dict = get_connection_params_from_docdb_api(secret_dict, db_cluster_arn)
            logger.info("setSecret: Successfully fetched connection params for Master Secret %s from DescribeDBClusters API." % arn)

        # For non-DocumentDB-made Master Secrets that are missing either `host` or `engine`, this will error below when checking for required connection params.

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    if secret_dict['engine'] != 'mongo':
        raise KeyError("Database engine must be set to 'mongo' in order to use this rotation lambda")

    # Parse and return the secret JSON string
    return secret_dict


def get_alt_username(current_username):
    """Gets the alternate username for the current_username passed in

    This helper function gets the username for the alternate user based on the passed in current username.

    Args:
        current_username (client): The current username

    Returns:
        AlternateUsername: Alternate username

    Raises:
        ValueError: If the new username length would exceed the maximum allowed

    """
    clone_suffix = "_clone"
    if current_username.endswith(clone_suffix):
        return current_username[:(len(clone_suffix) * -1)]
    else:
        return current_username + clone_suffix


def fetch_cluster_arn_from_tags(service_client, secret_arn):
    """Fetches DB Cluster ARN from the given secret's metadata.

    Fetches DB Cluster ARN from the given secret's metadata.

    Args:
        service_client (client): The secrets manager service client

        secret_arn (String): The secret ARN used in a DescribeSecrets API call to fetch the secret's metadata.

    Returns:
        db_cluster_arn (string): The DB Cluster ARN of the Primary DocumentDB cluster

    """
    metadata = service_client.describe_secret(SecretId=secret_arn)

    if 'Tags' not in metadata:
        logger.warning("setSecret: The secret %s is not a service-linked secret, so it does not have the aws:rds:primaryDBClusterArn AWS generated tag" % secret_arn)
        return None

    tags = metadata['Tags']

    # Check if DB Cluster ARN is present in secret Tags
    db_cluster_arn = None
    for tag in tags:
        if tag['Key'].lower() == 'aws:rds:primarydbclusterarn':
            db_cluster_arn = tag['Value']

    # DB Cluster ARN must be present in secret AWS generated tags to use this work-around
    if not db_cluster_arn:
        logger.warning("setSecret: DB Cluster ARN not present in AWS generated tags for secret %s" % secret_arn)
    elif len(db_cluster_arn) > MAX_RDS_DB_INSTANCE_ARN_LENGTH:
        logger.error("setSecret: %s is not a valid DB Cluster ARN. It exceeds the maximum length of %d." % (db_cluster_arn, MAX_RDS_DB_INSTANCE_ARN_LENGTH))
        raise ValueError("%s is not a valid DB Cluster ARN. It exceeds the maximum length of %d." % (db_cluster_arn, MAX_RDS_DB_INSTANCE_ARN_LENGTH))

    return db_cluster_arn


def get_connection_params_from_docdb_api(master_dict, master_cluster_arn):
    """Fetches connection parameters (`host`, `port`, etc.) from the DescribeDBClusters DocumentDB API using `master_instance_arn` in the master secret metadata as a filter.

    This helper function fetches connection parameters from the DescribeDBClusters DocumentDB API using `master_cluster_arn` in the master secret metadata as a filter.

    Args:
        master_dict (dictionary): The master secret dictionary that will be updated with connection parameters.

        master_cluster_arn (string): The DB cluster ARN from master secret AWS generated tag that will be used as a filter in DescribeDBClusters DocumentDB API calls.

    Returns:
        master_dict (dictionary): An updated master secret dictionary that now contains connection parameters such as `host`, `port`, etc.

    """
    # put connection parameters in master secret dictionary
    cluster_info = get_cluster_info_from_docdb_api(master_cluster_arn)
    master_dict['host'] = cluster_info['Endpoint']
    master_dict['port'] = cluster_info['Port']
    master_dict['engine'] = 'mongo'

    return master_dict


def get_cluster_info_from_docdb_api(cluster_id):
    """Fetches RDS cluster infomation from the DescribeDBClusters DocumentDB API using DBClusterIdentifier as a filter.

    This helper function fetches RDS cluster infomation from the DescribeDBClusters DocumentDB API using DBClusterIdentifier as a filter.

    Agrs:
        cluster_id (string): The DBClusterIdentifier of the RDS cluster to describe

    Returns:
        dbClusterResponse (dict): The DescribeDBClusters DocumentDB API response if found, otherwise None

    Rasies:
        Exception: If the DescribeDBClusters DocumentDB API returns an error

    """
    # Setup the client
    docdb_client = boto3.client('docdb')

    # Call DescribeDBClusters RDS API
    try:
        describe_response = docdb_client.describe_db_clusters(DBClusterIdentifier=cluster_id)
    except Exception as err:
        logger.error("setSecret: Encountered API error while fetching connection parameters from DescribeDBClusters DocumentDB API: %s" % err)
        raise Exception("Encountered API error while fetching connection parameters from DescribeDBClusters DocumentDB API: %s" % err)
    # Verify the instance was found
    clusters = describe_response['DBClusters']
    if not clusters:
        logger.error("setSecret: %s is not a valid DB Cluster ARN. No Clusters found when using DescribeDBClusters DocumentDB API to get connection params." % cluster_id)
        raise ValueError("%s is not a valid DB Cluster ARN. No Clusters found when using DescribeDBClusters DocumentDB API to get connection params." % cluster_id)

    # DB cluster identifiers are unique - can only be one result
    return clusters[0]


def get_environment_bool(variable_name, default_value):
    """Loads the environment variable and converts it to the boolean.

    Args:
        variable_name (string): Name of environment variable

        default_value (bool): The result will fallback to the default_value when the environment variable with the given name doesn't exist.

    Returns:
        bool: True when the content of environment variable contains either 'true', '1', 'y' or 'yes'
    """
    variable = os.environ.get(variable_name, str(default_value))
    return variable.lower() in ['true', '1', 'y', 'yes']


def get_random_password(service_client):
    """ Generates a random new password. Generator loads parameters that affects the content of the resulting password from the environment
    variables. When environment variable is missing sensible defaults are chosen.

    Supported environment variables:
        - EXCLUDE_CHARACTERS
        - PASSWORD_LENGTH
        - EXCLUDE_NUMBERS
        - EXCLUDE_PUNCTUATION
        - EXCLUDE_UPPERCASE
        - EXCLUDE_LOWERCASE
        - REQUIRE_EACH_INCLUDED_TYPE

    Args:
        service_client (client): The secrets manager service client

    Returns:
        string: The randomly generated password.
    """
    passwd = service_client.get_random_password(
        ExcludeCharacters=os.environ.get('EXCLUDE_CHARACTERS', '/@"\'\\'),
        PasswordLength=int(os.environ.get('PASSWORD_LENGTH', 32)),
        ExcludeNumbers=get_environment_bool('EXCLUDE_NUMBERS', False),
        ExcludePunctuation=get_environment_bool('EXCLUDE_PUNCTUATION', False),
        ExcludeUppercase=get_environment_bool('EXCLUDE_UPPERCASE', False),
        ExcludeLowercase=get_environment_bool('EXCLUDE_LOWERCASE', False),
        RequireEachIncludedType=get_environment_bool('REQUIRE_EACH_INCLUDED_TYPE', True)
    )
    return passwd['RandomPassword']
