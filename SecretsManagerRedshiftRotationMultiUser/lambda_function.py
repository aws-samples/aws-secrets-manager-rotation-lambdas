# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import logging
import os
import pg
import pgdb

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_REDSHIFT_CLUSTER_ARN_LENGTH = 256


def lambda_handler(event, context):
    """Secrets Manager Redshift Handler

    This handler uses the admin-user rotation scheme to rotate a Redshift user credential. During the first rotation, this
    scheme logs into the database as the admin user, creates a new user (appending _clone to the username), and grants the
    new user all of the permissions from the user being rotated. Once the secret is in this state, every subsequent rotation
    simply creates a new secret with the AWSPREVIOUS user credentials, changes that user's password, and then marks the
    latest secret as AWSCURRENT.

    The Secret SecretString is expected to be a JSON string with the following format:
    {
        'engine': <required: must be set to 'redshift'>,
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name, default to 'dev'>,
        'port': <optional: if not specified, default port 5439 will be used>,
        'masterarn': <required: the arn of the admin secret which will be used to create users/change passwords>
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
        # Get the alternate username swapping between the original user and the user with _clone appended to it
        current_dict['username'] = get_alt_username(current_dict['username'])
        current_dict['password'] = get_random_password(service_client)

        # Put the secret
        service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(current_dict), VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


def set_secret(service_client, arn, token):
    """Set the pending secret in the database

    This method tries to login to the database with the AWSPENDING secret and returns on success. If that fails, it
    tries to login with the admin credentials from the masterarn in the current secret. If this succeeds, it adds all
    grants for AWSCURRENT user to the AWSPENDING user, creating the user and/or setting the password in the process.
    Else, it throws a ValueError.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not valid JSON or admin credentials could not be used to login to DB

        KeyError: If the secret json does not contain the expected keys

    """
    current_dict = get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_dict = get_secret_dict(service_client, arn, "AWSPENDING", token)

    # First try to login with the pending secret, if it succeeds, return
    conn = get_connection(pending_dict)
    if conn:
        conn.close()
        logger.info("setSecret: AWSPENDING secret is already set as password in Redshift DB for secret arn %s." % arn)
        return

    # Make sure the user from current and pending match
    if get_alt_username(current_dict['username']) != pending_dict['username']:
        logger.error("setSecret: Attempting to modify user %s other than current user or clone %s" % (pending_dict['username'], current_dict['username']))
        raise ValueError(
            "Attempting to modify user %s other than current user or clone %s" % (pending_dict['username'], current_dict['username']))

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
    conn.close()

    # Use the admin arn from the current secret to fetch admin secret contents
    admin_arn = current_dict['masterarn']
    admin_dict = get_secret_dict(service_client, admin_arn, "AWSCURRENT", None, True)

    # Fetch dbname from the Child User
    admin_dict['dbname'] = current_dict.get('dbname', None)

    if current_dict['host'] != admin_dict['host']:
        logger.error("setSecret: Current database host %s is not the same host as admin %s" % (current_dict['host'], admin_dict['host']))
        raise ValueError("Current database host %s is not the same host as admin %s" % (current_dict['host'], admin_dict['host']))

    # Now log into the database with the admin credentials
    conn = get_connection(admin_dict)
    if not conn:
        logger.error("setSecret: Unable to log into database using credentials in admin secret %s" % admin_arn)
        raise ValueError("Unable to log into database using credentials in admin secret %s" % admin_arn)

    # Now set the password to the pending password
    try:
        with conn.cursor() as cur:
            # Get escaped usernames via quote_ident
            cur.execute("SELECT quote_ident(%s)", (pending_dict['username'],))
            pending_username = cur.fetchone()[0]

            # Check if the user exists, if not create it and grant it all permissions from the current role
            # If the user exists, just update the password
            cur.execute("SELECT usename FROM pg_user where usename = %s", (pending_dict['username'],))
            if len(cur.fetchall()) == 0:
                create_role = "CREATE USER %s" % pending_username
                cur.execute(create_role + " WITH PASSWORD %s", (pending_dict['password'],))

                # Grant the database permissions
                db_perm_types = ['CREATE', 'TEMPORARY', 'TEMP']
                for perm in db_perm_types:
                    cur.execute("SELECT QUOTE_IDENT(dat.datname) as datname FROM pg_database dat WHERE HAS_DATABASE_PRIVILEGE(%s, dat.datname , %s)",
                                (current_dict['username'], perm))
                    databases = [row.datname for row in cur.fetchall()]
                    if databases:
                        for database in databases:
                            cur.execute("GRANT %s ON DATABASE %s TO %s" % (perm, database, pending_username))

                # Grant table permissions
                table_perm_types = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'REFERENCES']
                for perm in table_perm_types:
                    cur.execute("SELECT QUOTE_IDENT(tab.schemaname) as schemaname, QUOTE_IDENT(tab.tablename) as tablename FROM pg_tables tab WHERE "
                                "HAS_TABLE_PRIVILEGE(%s, QUOTE_IDENT(tab.schemaname) + '.' + QUOTE_IDENT(tab.tablename) , %s) AND tab.schemaname NOT IN ('pg_internal','pg_automv')",
                                (current_dict['username'], perm))
                    tables = [row.schemaname + '.' + row.tablename for row in cur.fetchall()]
                    if tables:
                        cur.execute("GRANT %s ON TABLE %s TO %s" % (perm, ','.join(tables), pending_username))

                # Grant schema permissions
                table_perm_types = ['CREATE', 'USAGE']
                for perm in table_perm_types:
                    cur.execute(
                        "SELECT QUOTE_IDENT(schemaname) as schemaname FROM (SELECT DISTINCT schemaname FROM pg_tables) WHERE HAS_SCHEMA_PRIVILEGE(%s, schemaname, %s)",
                        (current_dict['username'], perm))
                    schemas = [row.schemaname for row in cur.fetchall()]
                    if schemas:
                        cur.execute("GRANT %s ON SCHEMA %s TO %s" % (perm, ','.join(schemas), pending_username))
            else:
                alter_role = "ALTER USER %s" % pending_username
                cur.execute(alter_role + " WITH PASSWORD %s", (pending_dict['password'],))

            conn.commit()
            logger.info("setSecret: Successfully set password for %s in Redshift DB for secret arn %s." % (pending_dict['username'], arn))
    finally:
        conn.close()


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
        # This is where the lambda will validate the user's permissions. Uncomment/modify the below lines to
        # tailor these validations to your needs
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT NOW()")
                conn.commit()
        finally:
            conn.close()

        logger.info("testSecret: Successfully signed into Redshift DB with AWSPENDING secret in %s." % arn)
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
        ResourceNotFoundException: If the secret with the specified arn does not exist

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
    """Gets a connection to Redshift DB from a secret dictionary

    This helper function tries to connect to the database grabbing connection info
    from the secret dictionary. If successful, it returns the connection, else None

    Args:
        secret_dict (dict): The Secret Dictionary

    Returns:
        Connection: The pgdb.Connection object if successful. None otherwise

    Raises:
        KeyError: If the secret json does not contain the expected keys

    """
    # Parse and validate the secret JSON string
    port = int(secret_dict['port']) if 'port' in secret_dict else 5439
    dbname = secret_dict['dbname'] if secret_dict.get('dbname') is not None else "dev"

    # Try to obtain a connection to the db
    try:
        conn = pgdb.connect(host=secret_dict['host'], user=secret_dict['username'], password=secret_dict['password'], database=dbname, port=port,
                            connect_timeout=5)
        logger.info("Successfully established connection as user '%s' with host: '%s'" % (secret_dict['username'], secret_dict['host']))
        return conn
    except pg.InternalError:
        return None


def get_secret_dict(service_client, arn, stage, token=None, admin_secret=False):
    """Gets the secret dictionary corresponding for the secret arn, stage, and token

    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        stage (string): The stage identifying the secret version

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        admin_secret (boolean): A flag that indicates if we are getting an admin secret.

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

    # Get tags associated with the secret if it is an admin secret
    if admin_secret:
        tags = get_tags_from_metadata(service_client, arn)
        # Fetch tag and tag type (redshift or redshift-serverless) from Redshift service-linked secrets
        redshift_system_tag_and_type = fetch_redshift_system_tag_from_tags(tags, arn)

        # Only fetch connection parameters if the secret is a service-linked secret, the parameter is set to None for non service-linked secrets
        if redshift_system_tag_and_type is not None:
            redshift_system_tag = redshift_system_tag_and_type[0]
            redshift_tag_type = redshift_system_tag_and_type[1]

            # Validate cluster_arn length before getting connection parameters
            cluster_arn = redshift_system_tag['Value']
            validate_cluster_arn(cluster_arn)

            # For Redshift service-linked secrets, use the cluster ARN to retrieve connection parameters from the Redshift APIs.
            if redshift_tag_type == "redshift-serverless":
                secret_dict = get_connection_params_from_redshift_serverless_api(secret_dict, cluster_arn)
            else:
                secret_dict = get_connection_params_from_redshift_api(secret_dict, cluster_arn)
            logger.info("setSecret: Successfully fetched connection params for the admin secret %s from the Redshift API." % arn)

            # Hardcode 'redshift' engine because this is a Redshift service-linked secret
            secret_dict['engine'] = 'redshift'

    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    # Run validations against the secret
    if secret_dict['engine'] != 'redshift':
        raise KeyError("Database engine must be set to 'redshift' in order to use this rotation lambda")

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


def fetch_redshift_system_tag_from_tags(tags, secret_arn):
    """Checks the secret for a tag with the Redshift cluster ARN. Only Redshift service-linked secrets will contain this tag.

    Args:
        tags (List of Tags): The tags contained in the secret metadata used to determine if the secret is a service-linked-secret or not.

        secret_arn (String): The secret ARN used in a DescribeSecrets API call to fetch the secret's metadata.

    Returns:
        (tag,type): Returns the Redshift System tag along with the type (redshift or redshift-serverless) if there is one, None otherwise

    """

    if not tags:
        logger.warning("setSecret: The secret %s is not a service-linked secret, so it does not have a tag aws:redshift:primaryclusterarn or aws:redshift-serverless:namespacearn" % secret_arn)
        return None

    for tag in tags:
        if tag['Key'].lower() == 'aws:redshift-serverless:namespacearn':
            return (tag, "redshift-serverless")
        elif tag['Key'].lower() == 'aws:redshift:primaryclusterarn':
            return (tag, "redshift")

    logger.warning("setSecret: The secret %s is not a service-linked secret, so it does not have a tag aws:redshift:primaryclusterarn or aws:redshift-serverless:namespacearn" % secret_arn)
    return None


def get_tags_from_metadata(service_client, secret_arn):
    """Retrieves the tags associated with the service-linked secret

    Args:
        service_client (client): The secrets manager service client

        secret_arn (String): The secret ARN used in a DescribeSecrets API call to fetch the secret's metadata.

    Returns:
        tags (list): The list of tags associated with the secret

    """
    metadata = service_client.describe_secret(SecretId=secret_arn)
    tags = metadata.get('Tags')

    return tags


def validate_cluster_arn(cluster_arn):
    """Validates cluster ARN length obtained from the Redshift System tag of the service-linked secret

    Args:
        cluster_arn: The Redshift Cluster ARN of the service-linked secret

    Raises:
        ValueError: If the cluster_arn length is greater than the maximum ARN length

    """

    if len(cluster_arn) > MAX_REDSHIFT_CLUSTER_ARN_LENGTH:
        logger.error("setSecret: The secret has a tag aws:redshift:primaryclusterarn or aws:redshift-serverless:namespacearn, but the ARN in the tag exceeds the maximum length %d." % MAX_REDSHIFT_CLUSTER_ARN_LENGTH)
        raise ValueError("The secret has a tag aws:redshift:primaryclusterarn or aws:redshift-serverless:namespacearn, but the ARN in the tag exceeds the maximum length %d." % MAX_REDSHIFT_CLUSTER_ARN_LENGTH)


def get_connection_params_from_redshift_serverless_api(admin_dict, namespace_arn):
    """Gets connection parameters such as host and port for the specified Redshift Serverless Instance

    This helper function uses the Redshift Serverless APIs to get connection parameters for the specified Redshift Namespace

    Args:
        admin_dict (dictionary): The admin secret dictionary that will be updated with connection parameters.

        namespace_arn (string): The namespace ARN used to find the workgroup associated with it.

    Returns:
        admin_dict (dictionary): An updated admin secret dictionary that now contains connection parameters such as `host` and `port`.

     Raises:
        Exception: If Redshift Serverless API returns an error

        ValueError: If the Redshift ListWorkgroups or ListNamespaces API's response contains no instances corresponding to the NamespaceId

    """
    # Set up the Redshift Serverless client
    redshift_serverless_client = boto3.client('redshift-serverless')

    if len(namespace_arn) == 0:
        logger.error("setSecret: The secret has a tag aws:redshift-serverless:namespacearn, but Redshift can't find namespace %s" % namespace_arn)
        raise ValueError("The secret has a tag aws:redshift-serverless:namespacearn, but Redshift can't find namespace %s" % namespace_arn)

    namespace_name = None
    # Call listNamespaces API to get namespaceName corresponding to the namespace_arn
    try:
        namespace_response = redshift_serverless_client.list_namespaces(maxResults=100)
        namespaces = namespace_response['namespaces']
    except Exception as err:
        logger.error("setSecret: Encountered API error while fetching connection parameters from ListNamespaces Redshift Serverless API: %s" % err)
        raise Exception("Encountered API error while fetching connection parameters from ListNamespaces Redshift Serverless API: %s" % err)

    for namespace in namespaces:
        if namespace_arn == namespace['namespaceArn']:
            namespace_name = namespace['namespaceName']
            break

    if not namespace_name:
        logger.error("setSecret: The secret has a tag aws:redshift-serverless:namespacearn, but Redshift can't find namespace %s" % namespace_arn)
        raise ValueError("The secret has a tag aws:redshift-serverless:namespacearn, but Redshift can't find namespace %s" % namespace_arn)

    admin_workgroup = None
    # Call the ListWorkgroups API to find the workgroup associated with the namespace, to get the host and port details
    try:
        workgroup_response = redshift_serverless_client.list_workgroups(maxResults=100)
        workgroups = workgroup_response['workgroups']
    except Exception as err:
        logger.error("setSecret: Encountered API error while fetching connection parameters from ListWorkgroups Redshift Serverless API: %s" % err)
        raise Exception("Encountered API error while fetching connection parameters from ListWorkgroups Redshift Serverless API: %s" % err)

    for workgroup in workgroups:
        if namespace_name == workgroup['namespaceName']:
            admin_workgroup = workgroup
            break

    if not admin_workgroup:
        logger.error("setSecret: The secret has a tag aws:redshift-serverless:namespacearn, but Redshift can't find workgroup associated with %s" % namespace_arn)
        raise ValueError("The secret has a tag aws:redshift-serverless:namespacearn, but Redshift can't find workgroup associated with %s" % namespace_arn)

    admin_dict['host'] = admin_workgroup['endpoint']['address']
    admin_dict['port'] = admin_workgroup['endpoint']['port']

    return admin_dict


def get_connection_params_from_redshift_api(admin_dict, admin_cluster_arn):
    """Gets connection parameters such as host and port for the specified Redshift cluster

    This helper function uses the Redshift DescribeClusters API to get connection parameters for the specified Redshift cluster

    Args:
        admin_dict (dictionary): The admin secret dictionary that will be updated with connection parameters.

        admin_cluster_arn (string): The cluster ARN to use as a filter in DescribeClusters Redshift API calls.

    Returns:
        admin_dict (dictionary): An updated admin secret dictionary that now contains connection parameters such as `host` and `port`.

    Raises:
        Exception: If Redshift DescribeClusters API returns an error

        ValueError: If the Redshift DescribeClusters API's response contains no instances or more than one instance
    """
    # Setup the Redshift client
    redshift_client = boto3.client('redshift')

    # extract the cluster identifier from the cluster ARN
    cluster_identifier = admin_cluster_arn.split(":")[-1]

    # Call DescribeClusters Redshift API
    try:
        describe_response = redshift_client.describe_clusters(ClusterIdentifier=cluster_identifier)
    except Exception as err:
        logger.error("setSecret: Encountered API error while fetching connection parameters from DescribeClusters Redshift API: %s" % err)
        raise Exception("Encountered API error while fetching connection parameters from DescribeClusters Redshift API: %s" % err)

    # Verify the instance was found
    clusters = describe_response['Clusters']
    if len(clusters) == 0:
        logger.error("setSecret: The secret has a tag aws:redshift:primaryclusterarn, but Redshift can't find the cluster defined in the tag: %s" % admin_cluster_arn)
        raise ValueError("The secret has a tag aws:redshift:primaryclusterarn, but Redshift can't find the cluster defined in the tag: %s" % admin_cluster_arn)

    # put connection parameters in admin secret dictionary
    primary_cluster = clusters[0]
    admin_dict['host'] = primary_cluster['Endpoint']['Address']
    admin_dict['port'] = primary_cluster['Endpoint']['Port']

    return admin_dict


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
        - EXCLUDE_PUNCTUATION
        - REQUIRE_EACH_INCLUDED_TYPE

    Redshift requires password to have at least one lower, one upper case and one number character. Because of that
    following options are omitted:
        - EXCLUDE_UPPERCASE
        - EXCLUDE_LOWERCASE
        - EXCLUDE_NUMBERS

    Args:
        service_client (client): The secrets manager service client

    Returns:
        string: The randomly generated password.
    """
    passwd = service_client.get_random_password(
        ExcludeCharacters=os.environ.get('EXCLUDE_CHARACTERS', '/@"\'\\:'),
        PasswordLength=int(os.environ.get('PASSWORD_LENGTH', 32)),
        ExcludePunctuation=get_environment_bool('EXCLUDE_PUNCTUATION', False),
        RequireEachIncludedType=get_environment_bool('REQUIRE_EACH_INCLUDED_TYPE', True)
    )
    return passwd['RandomPassword']
