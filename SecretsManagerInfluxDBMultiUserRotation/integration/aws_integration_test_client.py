# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
from pathlib import Path
from sys import platform
import time
import subprocess
import uuid
import os

import boto3
from integration_test_utils import random_string, logger


class AWSIntegrationTestClient:
    ROTATION_TIMEOUT_SECONDS = 60
    LAMBDA_FUNCTION_TAG_KEY = "tmp-influxdb-integration-test-lambda-function"
    LAMBDA_FUNCTION_TAG_VALUE = "multi-user-rotation-integration-lambda"
    LAMBDA_FUNCTION_RUNTIME = "python3.12"
    LAMBDA_FUNCTION_TIMEOUT_SECONDS = 180  # Three minutes
    SECRET_TAG_KEY = "tmp-influxdb-integration-test-secret"
    ADMIN_SECRET_TAG_VALUE = "multi-user-rotation-integration-test-admin-secret"
    USER_SECRET_TAG_VALUE = "multi-user-rotation-integration-test-user-secret"

    _boto3_session: boto3.Session
    _secrets_client = None
    _resource_client = None
    _lambda_client = None
    _region_name: str

    admin_secret_arn: str = ""
    user_secret_arn: str = ""
    rotation_lambda_name: str = ""
    rotation_lambda_arn: str = ""
    version_id: str = ""

    def __init__(self, region_name) -> None:
        self._region_name = region_name
        self._boto3_session = boto3.Session(region_name=self._region_name)
        self._secrets_client = self._boto3_session.client("secretsmanager")
        self._resource_client = self._boto3_session.client("resourcegroupstaggingapi")
        self._lambda_client = self._boto3_session.client("lambda")

    def get_aws_resources_by_tag(self, tag_key, tag_value):
        """
        Returns AWS resources using its tag key and tag value.

        :param str tag_key: The key of the tag.
        :param str tag_value: The value of the tag.
        :return: The resource information as a dict.
        """
        try:
            resources = self._resource_client.get_resources(
                TagFilters=[{"Key": tag_key, "Values": [tag_value]}]
            )["ResourceTagMappingList"]
            return resources
        except Exception as error:
            logger.error(repr(error))
            logger.error(
                f"An unexpected error occurred, resources with tag {tag_key}:{tag_value} could not be retrieved"
            )
            raise

    def create_admin_secret(
        self, engine, username, password, token, influxdb_id, org_name
    ):
        """
        Creates the admin secret dict in Secrets Manager, populating it with the provided values.

        :param str engine: The type of engine, "timstream-influxdb" is typical.
        :param str username: The username of the admin.
        :param str password: The password for the admin.
        :param str token: The token for the admin.
        :param str influxdb_id: The ID of the Timestream for InfluxDB instance where the admin exists.
        :param str org_name: The name of the existing org in the Timestream for InfluxDB instance to use.
        :return: None
        """
        secret_dict = {
            "engine": engine,
            "username": username,
            "password": password,
            "token": token,
            "static_operator_token": token,
            "dbIdentifier": influxdb_id,
            "org": org_name,
        }
        try:
            create_admin_secret_response = self._secrets_client.create_secret(
                Name=self.ADMIN_SECRET_TAG_VALUE + random_string(10),
                Description="A secret used for integration tests with the InfluxDB token multi-user rotation Lambda. "
                "This secret holds admin values, which will not be rotated.",
                SecretString=json.dumps(secret_dict),
                Tags=[
                    {"Key": self.SECRET_TAG_KEY, "Value": self.ADMIN_SECRET_TAG_VALUE}
                ],
            )
        except Exception:
            logger.error("Admin secret could not be created")
            raise
        self.admin_secret_arn = create_admin_secret_response["ARN"]

    def create_user_secret(self):
        """
        Creates the user secret in Secrets Manager, to be rotated, as empty JSON,
            and sets the user_secret_arn value.

        :return: None
        """
        try:
            secret_dict = {}
            create_user_secret_response = self._secrets_client.create_secret(
                Name=self.USER_SECRET_TAG_VALUE + random_string(10),
                Description="A secret used for integration tests with the InfluxDB token multi-user rotation Lambda. "
                "This secret holds user values, which will be rotated.",
                SecretString=json.dumps(secret_dict),
                Tags=[
                    {"Key": self.SECRET_TAG_KEY, "Value": self.USER_SECRET_TAG_VALUE}
                ],
            )
        except Exception:
            logger.error("User secret could not be created")
            raise
        self.user_secret_arn = create_user_secret_response["ARN"]

    def init_secrets(self, engine, username, password, token, influxdb_id, org_name):
        """
        Initializes admin and user secrets, getting their ARNs, and creating them if needed.

        :param str engine: The type of engine, "timstream-influxdb" is typical. To be used
            to create a new admin secret if an existing admin secret cannot be found.
        :param str username: The username of the admin. To be used
            to create a new admin secret if an existing admin secret cannot be found.
        :param str password: The password for the admin. To be used
            to create a new admin secret if an existing admin secret cannot be found.
        :param str token: The token for the admin. To be used
            to create a new admin secret if an existing admin secret cannot be found.
        :param str influxdb_id: The ID of the Timestream for InfluxDB instance where the admin exists. To be used
            to create a new admin secret if an existing admin secret cannot be found.
        :param str org_name: The name of the existing org in the Timestream for InfluxDB instance to use. To be used
            to create a new admin secret if an existing admin secret cannot be found.
        :return: None
        """
        existing_admin_secrets = self.get_aws_resources_by_tag(
            tag_key=self.SECRET_TAG_KEY, tag_value=self.ADMIN_SECRET_TAG_VALUE
        )
        if len(existing_admin_secrets) > 0:
            self.admin_secret_arn = existing_admin_secrets[0]["ResourceARN"]
            logger.info("Existing admin secret found")
        else:
            logger.info("No existing admin secret could be found, creating new secret")
            self.create_admin_secret(
                engine, username, password, token, influxdb_id, org_name
            )

        existing_user_secrets = self.get_aws_resources_by_tag(
            tag_key=self.SECRET_TAG_KEY, tag_value=self.USER_SECRET_TAG_VALUE
        )
        if len(existing_user_secrets) > 0:
            self.user_secret_arn = existing_user_secrets[0]["ResourceARN"]
            logger.info("Existing user secret found")
        else:
            logger.info("No existing user secret could be found, creating new secret")
            self.create_user_secret()

    def init_lambda_function(self, influxdb_arn):
        """
        Initializes the rotation lambda function, getting its ARN and name, and creating it
            if needed.

        :param str influxdb_arn: The ARN of the Timestream for InfluxDB instance, to be used to create
            permissions for the lambda function if it doesn't already exist.
        :return: None
        """
        # Check whether the lambda function already exists
        existing_lambda_functions = self.get_aws_resources_by_tag(
            tag_key=self.LAMBDA_FUNCTION_TAG_KEY,
            tag_value=self.LAMBDA_FUNCTION_TAG_VALUE,
        )
        if len(existing_lambda_functions) > 0:
            logger.info("Existing lambda rotation function found")
            self.rotation_lambda_arn = existing_lambda_functions[0]["ResourceARN"]
            try:
                rotation_lambda = self._lambda_client.get_function(
                    FunctionName=self.rotation_lambda_arn
                )
                self.rotation_lambda_name = rotation_lambda["Configuration"][
                    "FunctionName"
                ]
            except Exception:
                logger.error(
                    f"Getting rotation lambda function name for lambda function {self.rotation_lambda_arn} failed"
                )
                raise
        # Lambda function does not exist, create it
        else:
            logger.info("No existing rotation lambda function could be found")
            self.create_new_lambda_function(influxdb_arn=influxdb_arn)

    def create_new_lambda_function(self, influxdb_arn):
        """
        Creates a new rotation lambda function.

        :param str influxdb_arn: The ARN of the Timestream for InfluxDB instance, to be used to
            set permissions for the lambda function.
        :return: None
        """
        # Create permissions for lambda function
        iam_client = boto3.client("iam", region_name=self._region_name)
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        lambda_role_name = self.LAMBDA_FUNCTION_TAG_VALUE + "-role" + random_string(5)
        role_create_response = iam_client.create_role(
            RoleName=lambda_role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        lambda_role_arn = role_create_response["Role"]["Arn"]
        lambda_policy_name = (
            self.LAMBDA_FUNCTION_TAG_VALUE + "-policy" + random_string(5)
        )
        account_id = boto3.client("sts").get_caller_identity().get("Account")
        lambda_permissions = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "logs:CreateLogGroup",
                    "Resource": f"arn:aws:logs:{self._region_name}:{account_id}:*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": [
                        f"arn:aws:logs:{self._region_name}:{account_id}:log-group:/aws/lambda/{self.LAMBDA_FUNCTION_TAG_VALUE}*:*"
                    ],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:UpdateSecretVersionStage",
                    ],
                    "Resource": [f"{self.user_secret_arn}"],
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                    ],
                    "Resource": [f"{self.admin_secret_arn}"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetRandomPassword"],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "timestream-influxdb:GetDbInstance",
                    ],
                    "Resource": [f"{influxdb_arn}"],
                },
            ],
        }
        iam_client.put_role_policy(
            RoleName=lambda_role_name,
            PolicyName=lambda_policy_name,
            PolicyDocument=json.dumps(lambda_permissions),
        )

        # Create lambda function
        logger.info("Building lambda deployment")
        package_command = []
        if platform == "win32":
            package_command = [".\\build_deployment.ps1", "-D"]
        else:
            package_command = ["./build_deployment.sh", "-D"]
        subprocess.run(
            package_command,
            shell=False,
            input="y\n",
            text=True,
            stdout=subprocess.PIPE,
            cwd=os.path.pardir,
        )
        archive_path = Path("../influxdb-token-rotation-lambda.zip")
        if not archive_path.is_file():
            logger.error("Building rotation lambda function deployment failed")
            return
        logger.info("Creating lambda function")
        self.rotation_lambda_name = self.LAMBDA_FUNCTION_TAG_VALUE + random_string(5)
        with open(archive_path, "rb") as archive:
            lambda_create_response = self._lambda_client.create_function(
                FunctionName=self.rotation_lambda_name,
                Runtime=self.LAMBDA_FUNCTION_RUNTIME,
                Handler="lambda_function.lambda_handler",
                Role=lambda_role_arn,
                Timeout=self.LAMBDA_FUNCTION_TIMEOUT_SECONDS,
                Code={"ZipFile": archive.read()},
                PackageType="Zip",
                Environment={
                    "Variables": {
                        "SECRETS_MANAGER_ENDPOINT": f"https://secretsmanager.{self._region_name}.amazonaws.com"
                    }
                },
                Tags={self.LAMBDA_FUNCTION_TAG_KEY: self.LAMBDA_FUNCTION_TAG_VALUE},
            )
        self.rotation_lambda_arn = lambda_create_response["FunctionArn"]

        self._lambda_client.put_function_concurrency(
            FunctionName=self.rotation_lambda_name, ReservedConcurrentExecutions=100
        )

        # Allow secrets manager to invoke the lambda function
        self._lambda_client.add_permission(
            FunctionName=self.rotation_lambda_arn,
            StatementId="SecretsMangerInvoke",
            Action="lambda:InvokeFunction",
            Principal="secretsmanager.amazonaws.com",
            SourceArn=self.user_secret_arn,
        )

    def set_version_id(self, version_id=None):
        """
        Sets the version ID of the current secret, locally.
        If version_id is not provided, a uuid is generated.

        :param str version_id: The version ID to set, must be at least 32 characters in length.
        :return: None
        """
        if version_id is not None:
            self.version_id = version_id
        else:
            self.version_id = str(uuid.uuid4())

    def cancel_rotate_user_secret(self):
        """
        Cancels any ongoing rotation of the user secret and removes AWSPENDING from any
            version of the user secret.

        :return: None
        """
        self._secrets_client.cancel_rotate_secret(SecretId=self.user_secret_arn)
        self.remove_pending(arn=self.user_secret_arn)

    def wait_for_rotation(self, arn):
        """
        Waits for a rotation to end, whether with success or failure.

        :return: bool, whether the rotation succeeded.
        """
        # The only reliable way to determine whether a rotation succeeded is to check whether
        # the version ID has been set
        timeout = time.time() + self.ROTATION_TIMEOUT_SECONDS
        while time.time() < timeout:
            try:
                self._secrets_client.get_secret_value(
                    SecretId=arn,
                    VersionId=self.version_id,
                    VersionStage="AWSCURRENT",
                )
                return True
            except (
                self._secrets_client.exceptions.ResourceNotFoundException,
                self._secrets_client.exceptions.InvalidRequestException,
            ):
                pass
            time.sleep(5)
        return False

    def rotate_user_secret(self):
        """
        Rotates the user secret using the rotation lambda and a new version ID.

        :return: bool, whether the rotation succeeded.
        """
        # There should not be any rotations currently in progress, removing the AWSPENDING stage
        # will keep rotate_secret from believing a rotation is in progress
        self.cancel_rotate_user_secret()
        self.remove_pending(self.user_secret_arn)
        self.set_version_id()
        try:
            self._secrets_client.rotate_secret(
                SecretId=self.user_secret_arn,
                ClientRequestToken=self.version_id,
                RotationLambdaARN=self.rotation_lambda_arn,
                RotateImmediately=True,
            )
        except (
            self._secrets_client.exceptions.InvalidRequestException,
            self._secrets_client.exceptions.ResourceNotFoundException,
        ):
            raise
        return self.wait_for_rotation(self.user_secret_arn)

    def set_create_auth(self, create_auth):
        """
        Sets the environment variable of the rotation lambda to allow it to create
            credentials or tokens if necessary.

        :param bool create_auth: The value to set the environment variable to.
        :return: None
        """
        create_auth_str = "false"
        if create_auth:
            create_auth_str = "true"
        self._lambda_client.update_function_configuration(
            FunctionName=self.rotation_lambda_arn,
            Environment={
                "Variables": {
                    "SECRETS_MANAGER_ENDPOINT": f"https://secretsmanager.{self._region_name}.amazonaws.com",
                    "AUTHENTICATION_CREATION_ENABLED": create_auth_str,
                }
            },
        )
        # Wait for configuration to change
        timeout = time.time() + 60  # One minute from now
        while time.time() < timeout:
            response = self._lambda_client.get_function_configuration(
                FunctionName=self.rotation_lambda_arn
            )
            if (
                "LastUpdateStatus" in response
                and response["LastUpdateStatus"] == "Successful"
            ):
                logger.debug(
                    f'Successfully updated create auth value to "{create_auth_str}"'
                )
                break
            elif (
                "LastUpdateStatus" in response
                and response["LastUpdateStatus"] == "Failed"
            ):
                logger.error(
                    f'Failed to udpate create auth environment variable to "{create_auth_str}"'
                )
                break
            # Still in progress
            time.sleep(5)
        if time.time() >= timeout:
            logger.error(
                f'Failed to udpate create auth environment variable to "{create_auth_str}"'
            )

    def remove_pending(self, arn):
        """
        Removes the AWSPENDING stage from any and all version IDs for a secret.
            The existence of an AWSPENDING stage can cause the secrets manager to consider a secret
            still in rotation.

        :param str arn: The secret ARN to remove the AWSPENDING stage from.
        :return: None
        """
        try:
            versions = self._secrets_client.describe_secret(SecretId=arn)[
                "VersionIdsToStages"
            ]
            for key, val in versions.items():
                if "AWSPENDING" in val:
                    self._secrets_client.update_secret_version_stage(
                        RemoveFromVersionId=key,
                        SecretId=arn,
                        VersionStage="AWSPENDING",
                    )
        except Exception as error:
            logger.error(repr(error))
            logger.error("Removing AWSPENDING stage from secret version failed")

    def get_admin_secret_dict(self):
        """
        Gets and returns the admin secret, as a dict, from Secrets Manager.

        :return: dict, the admin secret.
        """
        return self.get_secret_dict(self.admin_secret_arn)

    def get_user_secret_dict(self):
        """
        Gets and returns the user secret, as a dict, from Secrets Manager.

        :return: dict, the user secret.
        """
        return self.get_secret_dict(self.user_secret_arn)

    def get_secret_dict(self, secret_arn):
        """
        Gets and returns the secret from Secrets Manager, as a dict, with
            matching ARN.
        :param str secret_arn: The ARN of the secret to return.
        :return: dict, the secret.
        """
        return json.loads(
            self._secrets_client.get_secret_value(SecretId=secret_arn)["SecretString"]
        )

    def post_user_secret(self, secret_dict):
        """
        Updates the user secret in Amazon Secrets Manager to contain the values in secret_dict.

        :param dict secret_dict: The dict to use in Secrets Manager as the user secret.
        :return: None
        """
        self.post_secret(secret_dict=secret_dict, secret_arn=self.user_secret_arn)

    def post_admin_secret(self, secret_dict):
        """
        Updates the admin secret in Amazon Secrets Manager to contain the values in secret_dict.

        :param dict secret_dict: The dict to use in Secrets Manager as the admin secret.
        :return: None
        """
        self.post_secret(secret_dict=secret_dict, secret_arn=self.admin_secret_arn)

    def post_secret(self, secret_dict, secret_arn):
        """
        Updates the secret with matching ARN in Amazon Secrets Manager to contain the values in secret_dict.

        :param dict secret_dict: The dict to use in Secrets Manager.
        :param str secret_arn: The ARN of the secret to set.
        :return: None
        """
        self.set_version_id()
        try:
            self._secrets_client.update_secret(
                SecretId=secret_arn,
                ClientRequestToken=self.version_id,
                SecretString=json.dumps(secret_dict),
            )
        except Exception as error:
            logger.error(repr(error))
            logger.error(f"Failed to update secret with ARN {secret_arn}")

    def teardown(self):
        """
        Deletes all resources created by AWSIntegrationTestClient.

        :return: None
        """
        self.delete_admin_secret()
        self.delete_user_secret()
        self.delete_lambda()

    def delete_admin_secret(self):
        """
        Finds and deletes the admin secret in Secrets Manager by using its ARN.

        :return: None
        """
        logger.info("Deleting admin secret")
        self.delete_secret(secret_arn=self.admin_secret_arn)

    def delete_user_secret(self):
        """
        Finds and deletes the user secret in Secrets Manager by using its ARN.

        :return: None
        """
        logger.info("Deleting user secret")
        self.delete_secret(secret_arn=self.user_secret_arn)

    def delete_secret(self, secret_arn):
        """
        Finds and deletes a secret in Secrets Manager by using its ARN.

        :param str secret_arn: The ARN of the secret to delete.
        :return: None
        """
        try:
            self._secrets_client.delete_secret(
                SecretId=secret_arn, ForceDeleteWithoutRecovery=True
            )
        except Exception as error:
            logger.error(repr(error))
            logger.error(f"Failed to delete secret with ARN {secret_arn}")

    def delete_lambda(self):
        """
        Finds and deletes the rotation lambda using its name.

        :return: None
        """
        logger.info("Deleting lambda function")
        try:
            self._lambda_client.delete_function(FunctionName=self.rotation_lambda_arn)
        except Exception as error:
            logger.error(repr(error))
            logger.error("Failed to delete lambda function")
