# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import logging
import os
import ibm_db

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_RDS_DB_INSTANCE_ARN_LENGTH = 256


def lambda_handler(event, context):
    """Secrets Manager RDS Db2 Handler

    This handler uses the master-user rotation scheme to rotate an RDS Db2 user credential. During the first rotation, this
    scheme logs into the database as the master user, creates a new user (appending _clone to the username), and grants the
    new user all of the permissions from the user being rotated. Once the secret is in this state, every subsequent rotation
    simply creates a new secret with the AWSPREVIOUS user credentials, changes that user's password, and then marks the
    latest secret as AWSCURRENT.

    The Secret SecretString is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'db2'>,
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name>,
        'port': <optional: if not specified, default port 50000 will be used>,
        'masterarn': <required: the arn of the master secret which will be used to create users/change passwords>
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

        # Get exclude characters from environment variable
        exclude_characters = os.environ['EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else '/@"\'\\;'
        # Generate a random password
        passwd = service_client.get_random_password(ExcludeCharacters=exclude_characters)
        current_dict['password'] = passwd['RandomPassword']

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
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)

    # First try to login with the pending secret, if it succeeds, return
    conn = get_connection(pending_dict)
    if conn:
        ibm_db.close(conn)
        logger.info("setSecret: AWSPENDING secret is already set as password in Db2 DB for secret arn %s." % arn)
        return

    # Make sure the user from current and pending match
    if get_alt_username(current_dict['username']) != pending_dict['username']:
        logger.error("setSecret: Attempting to modify user %s other than current user or clone %s" % (pending_dict['username'], current_dict['username']))
        raise ValueError("Attempting to modify user %s other than current user or clone %s" % (pending_dict['username'], current_dict['username']))

    # Make sure the host from current and pending match
    if current_dict['host'] != pending_dict['host']:
        logger.error("setSecret: Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))
        raise ValueError("Attempting to modify user for host %s other than current host %s" % (pending_dict['host'], current_dict['host']))

    # Now try the current password
    conn = get_connection(current_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using current credentials for secret %s" % arn)
        raise ValueError("Unable to log into database using current credentials for secret %s" % arn)
    ibm_db.close(conn)

    # Use the master arn from the current secret to fetch master secret contents
    master_arn = current_dict['masterarn']
    master_dict = get_secret_dict(service_client, master_arn, "AWSCURRENT", None, True)

    # Fetch dbname from the Child User
    master_dict['dbname'] = current_dict.get('dbname', None)

    # Validate that the current secret host and master secret host match
    if current_dict['host'] != master_dict['host'] and not is_rds_replica_database(current_dict, master_dict):
        # If current dict is a replica of the master dict, can proceed
        logger.error("setSecret: Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))
        raise ValueError("Current database host %s is not the same host as/rds replica of master %s" % (current_dict['host'], master_dict['host']))

    # If connection was successful, create two connections, one to child dbname and one to rdsadmin
    admin_conn = get_connection(master_dict, True)
    if not admin_conn:
        logger.error("setSecret: Unable to log into rdsadmin database using credentials in master secret %s" % master_arn)
        raise ValueError("Unable to log into rdsadmin database using credentials in master secret %s" % master_arn)

    try:
        db_conn = get_connection(master_dict, False)
    finally:
        if not db_conn:
            ibm_db.close(admin_conn)
            logger.error("setSecret: Unable to log into database using credentials in master secret %s" % master_arn)
            raise ValueError("Unable to log into database using credentials in master secret %s" % master_arn)

    # Try to create the user first
    try:
        sql_stmt = "call rdsadmin.add_user(?, ?, 'group')"
        stmt = ibm_db.prepare(admin_conn, sql_stmt)
        ibm_db.bind_param(stmt, 1, pending_dict['username'])
        ibm_db.bind_param(stmt, 2, pending_dict['password'])
        ibm_db.execute(stmt)
    except Exception as e:
        if not "Username %s already exists" % pending_dict['username'] in str(e):
            ibm_db.close(admin_conn)
            ibm_db.close(db_conn)
            logger.error("setSecret: Unable to create user %s" % pending_dict['username'])
            raise ValueError("Unable to create user %s" % pending_dict['username'])

    # Copy permissions
    perm_to_cmd_map = {
        "EXTERNALROUTINE": "CREATE_EXTERNAL_ROUTINE",
        "IMPLSCHEMA": "IMPLICIT_SCHEMA",
        "NOFENCE": "CREATE_NOT_FENCED_ROUTINE",
        "QUIESCECONNECT": "QUIESCE_CONNECT",
        "SECURITYADM": "SECADM",
        "CREATESECURE": "CREATE_SECURE_OBJECT"
    }

    # See if there are any database permissions for the current user and copy them to pending user
    try:
        # Make sure the user exists in the database
        pending_username = None
        list_stmt = "call rdsadmin.list_users()"
        list_resp = ibm_db.exec_immediate(admin_conn, list_stmt)
        user_list = ibm_db.fetch_assoc(list_resp)['1'].split("\n")
        # Loop through the user list. First 3 rows are headers and last 3 are footers for the list_users procedure
        for user_index in range(3, len(user_list) - 3):
            if user_list[user_index].upper().startswith("%s\t" % pending_dict['username'].upper()):
                pending_username = pending_dict['username'].upper()
                break

        if not pending_username:
            logger.error("setSecret: User %s does not exist in database" % pending_dict['username'])
            raise ValueError("User %s does not exist in database" % pending_dict['username'])

        sql_stmt = "SELECT * FROM SYSCAT.DBAUTH WHERE GRANTEE = ? AND GRANTEETYPE = 'U'"
        stmt = ibm_db.prepare(db_conn, sql_stmt)
        ibm_db.bind_param(stmt, 1, current_dict['username'].upper())
        ibm_db.execute(stmt)
        dictionary = ibm_db.fetch_assoc(stmt)
        while dictionary is not False:
            for perm in dictionary:
                if dictionary[perm] == 'Y' and perm.endswith("AUTH"):
                    stripped_cmd = perm[:len(perm) - 4]
                    if stripped_cmd in perm_to_cmd_map:
                        stripped_cmd = perm_to_cmd_map[stripped_cmd]
                    create_sql_stmt = "GRANT %s ON DATABASE TO USER %s" % (stripped_cmd, pending_username)
                    ibm_db.exec_immediate(db_conn, create_sql_stmt)
            dictionary = ibm_db.fetch_assoc(stmt)

        # Now change the password
        sql_stmt = "call rdsadmin.change_password(?, ?)"
        stmt = ibm_db.prepare(admin_conn, sql_stmt)
        ibm_db.bind_param(stmt, 1, pending_dict['username'])
        ibm_db.bind_param(stmt, 2, pending_dict['password'])
        ibm_db.execute(stmt)
        logger.info("setSecret: Successfully set password for %s in Db2 DB for secret arn %s." % (pending_dict['username'], arn))
    finally:
        ibm_db.close(admin_conn)
        ibm_db.close(db_conn)


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
    conn = get_connection(get_secret_dict(service_client, arn, "AWSPENDING", token))
    if conn:
        # User successfully connected to database using new password, close the connection.
        # More tests can be added to test for specific user permissions here.
        ibm_db.close(conn)

        logger.info("testSecret: Successfully signed into Db2 DB with AWSPENDING secret in %s." % arn)
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
        new_username = current_username[:(len(clone_suffix) * -1)]
        if not new_username:
            raise ValueError("Invalid username, username must not be empty after _clone suffix is removed")
        return new_username
    else:
        new_username = current_username + clone_suffix
        if len(new_username) > 16:
            raise ValueError("Unable to clone user, username length with _clone appended would exceed 16 characters")
        return new_username


def get_connection(secret_dict, use_admin=False):
    """Gets a connection to Db2 DB from a secret dictionary

    This helper function uses connectivity information from the secret dictionary to initiate
    connection attempt(s) to the database.

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Connection: The IBM_DBConnection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Parse and validate the secret JSON string
    port = int(secret_dict['port']) if 'port' in secret_dict else 50000
    dbname = secret_dict['dbname'] if 'dbname' in secret_dict else None
    dbname = "rdsadmin" if use_admin else dbname

    return connect_and_authenticate(secret_dict, port, dbname)


def connect_and_authenticate(secret_dict, port, dbname):
    """Attempt to connect and authenticate to a Db2 instance

    This helper function tries to connect to the database using connectivity info passed in.
    If successful, it returns the connection, else None

    Args:
        - secret_dict (dict): The Secret Dictionary
        - port (int): The databse port to connect to
        - dbname (str): Name of the database

    Returns:
        Connection: The IBM_DBConnection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Try to obtain a connection to the db
    try:
        connect_string = "DATABASE=%s;HOSTNAME=%s;PORT=%d;PROTOCOL=TCPIP;UID=%s;PWD=%s;" % (dbname, secret_dict['host'], port, secret_dict['username'], secret_dict['password'])
        conn = ibm_db.connect(connect_string, "", "")
        logger.info("Successfully established connection as user '%s' with host: '%s'" % (secret_dict['username'], secret_dict['host']))
        return conn
    except Exception:
        logger.warning("Unable to establish database connection", exc_info=True)
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
        # If this is an RDS-made Master Secret, we can fetch `host` and other connection params
        # from the DescribeDBInstances RDS API using the DB Instance ARN as a filter.
        # The DB Instance ARN is fetched from the RDS-made Master Secret's System Tags.
        db_instance_arn = fetch_instance_arn_from_system_tags(service_client, arn)
        if db_instance_arn is not None:
            secret_dict = get_connection_params_from_rds_api(secret_dict, db_instance_arn)
            logger.info("setSecret: Successfully fetched connection params for Master Secret %s from DescribeDBInstances API." % arn)

        # For non-RDS-made Master Secrets that are missing `host`, this will error below when checking for required connection params.

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    if not secret_dict['engine'].startswith('db2'):
        raise KeyError("Database engine must be set to 'db2' in order to use this rotation lambda")

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
    """Fetches DB Instance ARN from the given secret's metadata.

    Fetches DB Instance ARN from the given secret's metadata.

    Args:
        service_client (client): The secrets manager service client

        secret_arn (String): The secret ARN used in a DescribeSecrets API call to fetch the secret's metadata.

    Returns:
        db_instance_arn (String): The DB Instance ARN of the Primary RDS Instance

    """
    metadata = service_client.describe_secret(SecretId=secret_arn)

    if 'Tags' not in metadata:
        logger.warning("setSecret: The secret %s is not a service-linked secret, so it does not have a tag aws:rds:primarydbinstancearn" % secret_arn)
        return None

    tags = metadata['Tags']

    # Check if DB Instance ARN is present in secret Tags
    db_instance_arn = None
    for tag in tags:
        if tag['Key'].lower() == 'aws:rds:primarydbinstancearn':
            db_instance_arn = tag['Value']

    # DB Instance ARN must be present in secret System Tags to use this work-around
    if db_instance_arn is None:
        logger.warning("setSecret: DB Instance ARN not present in Metadata System Tags for secret %s" % secret_arn)
    elif len(db_instance_arn) > MAX_RDS_DB_INSTANCE_ARN_LENGTH:
        logger.error("setSecret: %s is not a valid DB Instance ARN. It exceeds the maximum length of %d." % (db_instance_arn, MAX_RDS_DB_INSTANCE_ARN_LENGTH))
        raise ValueError("%s is not a valid DB Instance ARN. It exceeds the maximum length of %d." % (db_instance_arn, MAX_RDS_DB_INSTANCE_ARN_LENGTH))

    return db_instance_arn


def get_connection_params_from_rds_api(master_dict, master_instance_arn):
    """Fetches connection parameters (`host`, `port`, etc.) from the DescribeDBInstances RDS API using `master_instance_arn` in the master secret metadata as a filter.

    This helper function fetches connection parameters from the DescribeDBInstances RDS API using `master_instance_arn` in the master secret metadata as a filter.

    Args:
        master_dict (dictionary): The master secret dictionary that will be updated with connection parameters.

        master_instance_arn (string): The DB Instance ARN from master secret System Tags that will be used as a filter in DescribeDBInstances RDS API call.

    Returns:
        master_dict (dictionary): An updated master secret dictionary that now contains connection parameters such as `host`, `port`, etc.

    Raises:
        Exception: If there is some error/throttling when calling the DescribeDBInstances RDS API

        ValueError: If the DescribeDBInstances RDS API Response contains no Instances
    """
    # Setup the client
    rds_client = boto3.client('rds')

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

    # Always set the database to rdsadmin as this is required to change password
    master_dict['dbname'] = "rdsadmin"

    return master_dict
