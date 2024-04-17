# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import argparse
import os
import sys
import unittest

from aws_integration_test_client import AWSIntegrationTestClient
from influxdb_integration_test_client import InfluxDBIntegrationTestClient

sys.path.insert(1, os.path.realpath(os.path.pardir))
from lambda_function import (
    create_all_access_token_perms,
    create_custom_token_perms,
)
from integration_test_utils import logger

aws_region_name = ""

# Whether to delete all AWS resources after testing
cleanup = False


class BaseTestCases:
    class BaseTestCase(unittest.TestCase):
        user_secret_dict = {}
        aws_it_client: AWSIntegrationTestClient
        influxdb_it_client: InfluxDBIntegrationTestClient

        @classmethod
        def setUpClass(cls):
            cls.aws_it_client = AWSIntegrationTestClient(region_name=aws_region_name)
            cls.influxdb_it_client = InfluxDBIntegrationTestClient(
                region_name=aws_region_name
            )
            try:
                cls.influxdb_it_client.init_timestream_for_influxdb()
                cls.aws_it_client.init_secrets(
                    engine=cls.influxdb_it_client.TIMESTREAM_INFLUXDB_ENGINE,
                    username=cls.influxdb_it_client.INFLUXDB_ADMIN_USERNAME,
                    password=cls.influxdb_it_client.influxdb_admin_password,
                    token=cls.influxdb_it_client.static_operator_token,
                    influxdb_id=cls.influxdb_it_client.influxdb_id,
                    org_name=cls.influxdb_it_client.INFLUXDB_ORG_NAME,
                )
                cls.aws_it_client.init_lambda_function(
                    influxdb_arn=cls.influxdb_it_client.influxdb_arn
                )
            except Exception as error:
                logger.error(repr(error))
                logger.error("Test initialization failed. Exiting . . .")
                exit(1)

        def setUp(self):
            """
            Overrides unittest.TestCase.setUp, called before each test runs
            """
            assert self.aws_it_client is not None
            assert self.influxdb_it_client is not None
            # Create a new InfluxDB token and initialize self.user_secret_dict to default values
            self.influxdb_it_client.create_current_auth()
            self.set_user_secret_dict(
                token_type=self.influxdb_it_client.TOKEN_TYPE_OPERATOR,
                token=self.influxdb_it_client.current_auth.token,
            )
            # Stop a rotation if it was left in progress
            self.aws_it_client.cancel_rotate_user_secret()

        def set_user_secret_dict(
            self,
            operator_token_arn=None,
            db_identifier=None,
            org_name=None,
            token_type=None,
            token=None,
            write_bucket=None,
            read_bucket=None,
            permissions=None,
            username=None,
            password=None,
        ):
            # Mandatory fields
            secret_dict = {
                "engine": self.influxdb_it_client.TIMESTREAM_INFLUXDB_ENGINE,
                "operatorTokenArn": operator_token_arn
                if operator_token_arn is not None
                else self.aws_it_client.admin_secret_arn,
                "dbIdentifier": db_identifier
                if db_identifier is not None
                else self.influxdb_it_client.influxdb_id,
                "org": org_name
                if org_name is not None
                else self.influxdb_it_client.INFLUXDB_ORG_NAME,
            }
            if token_type is not None:
                secret_dict["type"] = token_type
            if token is not None:
                secret_dict["token"] = token
            if permissions is not None:
                secret_dict["permissions"] = permissions
            if read_bucket is not None:
                secret_dict["readBucket"] = read_bucket
            if write_bucket is not None:
                secret_dict["writeBucket"] = write_bucket
            if username is not None:
                secret_dict["username"] = username
            if password is not None:
                secret_dict["password"] = password
            self.user_secret_dict = secret_dict

        def assert_token_is_scoped_to_primary_org(self, token):
            self.assertGreater(
                len(self.influxdb_it_client.get_primary_org(token=token)), 0
            )
            self.assertEqual(
                len(self.influxdb_it_client.get_secondary_org(token=token)), 0
            )

        def tearDown(self):
            """
            Overrides unittest.TestCase.tearDown, called after each test runs

            Resets the admin secret to default values, resets the admin's password in Timestream for InfluxDB,
            ensures the non-existent user stays non-existent, and deletes any token that is not the admin's token.
            """
            if self.aws_it_client is not None:
                # Stop a rotation if it was left in progress
                self.aws_it_client.cancel_rotate_user_secret()
                # Reset admin token value to an authenticated token
                admin_secret_dict = self.aws_it_client.get_admin_secret_dict()
                admin_secret_dict["token"] = (
                    self.influxdb_it_client.static_operator_token
                )
                self.aws_it_client.set_version_id()
                self.aws_it_client.post_admin_secret(secret_dict=admin_secret_dict)
                self.aws_it_client.set_create_auth(False)
            if self.influxdb_it_client is not None:
                self.influxdb_it_client.reset_admin_password()
                # The non-existent user must remain non-existent
                self.influxdb_it_client.reset_non_existent_user()
                self.influxdb_it_client.delete_non_admin_tokens()

        @classmethod
        def tearDownClass(cls):
            if cls.influxdb_it_client.influxdb_client is not None:
                cls.influxdb_it_client.influxdb_client.close()
            if cleanup:
                cls.aws_it_client.teardown()
                cls.influxdb_it_client.teardown()


class SecretsTestCase(BaseTestCases.BaseTestCase):
    def test_operator_token_rotation_no_token(self):
        """
        Failure rotation for operator token without token provided.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_OPERATOR
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertNotIn("token", new_secret_dict)

    def test_random_operator_token_rotation(self):
        """
        Failure rotation for random operator token.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_OPERATOR, token="random-token"
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

    def test_retrigger_random_operator_token_rotation(self):
        """
        Failure re-rotation random operator token.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_OPERATOR, token="random-token"
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]

        # First rotation
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        # Second rotation
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

    def test_operator_token_rotation_invalid_operator_token_arn(self):
        """
        Failure rotation with invalid operatorTokenArn.
        """
        invalid_arn = "invalid-arn-for-admin-secret"
        self.user_secret_dict["operatorTokenArn"] = invalid_arn
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.aws_it_client.set_create_auth(True)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

    def test_all_access_token_rotation_no_token_create_auth_disabled(self):
        """
        Failure rotation for all access token with missing token and create auth disabled.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_ALL_ACCESS
        )
        # Set the user secret using the new all access token
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertNotIn("token", new_secret_dict)

    def test_all_access_token_rotation_escalate_to_operator(self):
        """
        Failure to escalate an all access token to an operator token.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_ALL_ACCESS
        )
        # Set the user secret using the new all access token
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.aws_it_client.set_create_auth(True)
        # Rotation should succeed, the escalation of privileges should fail
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertIn("token", new_secret_dict)
        new_token = new_secret_dict["token"]

        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_OPERATOR, token=new_token
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)

        # All access tokens will have permissions scoped to an organization
        # if the token cannot be used to get information about another organization, then it has not
        # been escalated to an operator token
        self.assert_token_is_scoped_to_primary_org(token=new_token)

    def test_username_and_password_rotation_non_existent_user_create_auth_disabled(
        self,
    ):
        """
        Failure to rotate credentials for non-existent user with create auth disabled.
        """
        self.set_user_secret_dict(
            username=self.influxdb_it_client.NON_EXISTENT_USERNAME
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertNotIn("password", new_secret_dict)

    def test_username_and_password_rotation_incorrect_password(self):
        """
        Wrong password set for user fails.
        """
        self.set_user_secret_dict(
            username=self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME,
            password="incorrect-password",
        )
        old_password = self.user_secret_dict["password"]
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_password = self.aws_it_client.get_user_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

    def test_operator_token_rotation_missing_mandatory_fields(self):
        """
        Failures for token rotation without mandatory secret fields.

        Mandatory secret fields are "engine," "org," "dbIdentifier," "token," and "operatorTokenArn."
        """
        self.user_secret_dict.pop("engine", None)
        self.user_secret_dict.pop("dbIdentifier", None)
        self.user_secret_dict.pop("org", None)
        self.user_secret_dict.pop("operatorTokenArn", None)
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        self.user_secret_dict["engine"] = (
            self.influxdb_it_client.TIMESTREAM_INFLUXDB_ENGINE
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        self.user_secret_dict["dbIdentifier"] = self.influxdb_it_client.influxdb_id
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        self.user_secret_dict["operatorTokenArn"] = self.aws_it_client.admin_secret_arn
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        self.user_secret_dict["org"] = self.influxdb_it_client.INFLUXDB_ORG_NAME
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        # Note the inclusion of our generated version ID, as it should now be used as AWSCURRENT
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)

    def test_username_and_password_rotation_missing_mandatory_fields(self):
        """
        Failures for credential rotation without mandatory secret fields.

        Mandatory secret fields are "engine," "dbIdentifier," "username," "password," and "operatorTokenArn."
        """
        self.set_user_secret_dict(
            password=self.influxdb_it_client.influxdb_admin_password
        )
        self.user_secret_dict.pop("engine", None)
        self.user_secret_dict.pop("dbIdentifier", None)
        self.user_secret_dict.pop("username", None)
        self.user_secret_dict.pop("operatorTokenArn", None)
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_password = self.user_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_password = self.aws_it_client.get_user_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

        self.user_secret_dict["engine"] = (
            self.influxdb_it_client.TIMESTREAM_INFLUXDB_ENGINE
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_password = self.user_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_password = self.aws_it_client.get_user_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

        self.user_secret_dict["username"] = (
            self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_password = self.user_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_password = self.aws_it_client.get_user_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

        self.user_secret_dict["dbIdentifier"] = self.influxdb_it_client.influxdb_id
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_password = self.user_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), False)
        new_password = self.aws_it_client.get_user_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

        self.user_secret_dict["operatorTokenArn"] = self.aws_it_client.admin_secret_arn
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_password = self.user_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_password = self.aws_it_client.get_user_secret_dict()["password"]
        self.assertNotEqual(old_password, new_password)

    def test_operator_token_rotation(self):
        """
        Successful rotation for operator token with token provided.
        """
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_user_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertNotEqual(old_token, new_user_token)

    def test_retrigger_operator_token_rotation(self):
        """
        Successful re-rotation for operator token.
        """
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)

        old_token = new_token
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)

    def test_all_access_token_rotation_no_token_create_auth_enabled(self):
        """
        Successful rotation for allAccess token without token provided.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_ALL_ACCESS
        )
        # Set the user secret using the new all access token
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.aws_it_client.set_create_auth(True)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertIn("token", new_secret_dict)

        new_token = new_secret_dict["token"]
        self.assert_token_is_scoped_to_primary_org(token=new_token)

    def test_all_access_token_rotation_create_auth_disabled(self):
        """
        Successful rotation for allAccess token with token provided.
        """
        self.influxdb_it_client.create_current_auth(
            create_all_access_token_perms(
                org_id=self.influxdb_it_client.influxdb_org_id,
                user_id=self.influxdb_it_client.influxdb_admin_id,
            )
        )
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_ALL_ACCESS,
            token=self.influxdb_it_client.current_auth.token,
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)
        self.assert_token_is_scoped_to_primary_org(token=new_token)

    def test_retrigger_all_access_token_rotation_no_token_create_auth_enabled(self):
        """
        Successful re-rotation for allAccess token.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_ALL_ACCESS
        )
        # Set the user secret using the new all access token
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.aws_it_client.set_create_auth(True)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertIn("token", new_secret_dict)
        old_token = new_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertIn("token", new_secret_dict)
        new_token = new_secret_dict["token"]
        self.assertNotEqual(old_token, new_token)

    def test_custom_token_rotation_create_auth_enabled(self):
        """
        Successful rotation for custom token with token provided.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_CUSTOM,
            permissions=["read-orgs"],
        )
        self.influxdb_it_client.create_current_auth(
            token_perms=create_custom_token_perms(
                org_id=self.influxdb_it_client.influxdb_org_id,
                current_secret_dict=self.user_secret_dict,
            )
        )
        # Add the new custom token to the user secret dict
        self.user_secret_dict["token"] = self.influxdb_it_client.current_auth.token
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_token = self.user_secret_dict["token"]

        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)

        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)
        self.assert_token_is_scoped_to_primary_org(token=new_token)

    def test_custom_token_rotation_no_token_create_auth_enabled(self):
        """
        Successful rotation for custom token without token provided.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_CUSTOM,
            permissions=["read-orgs"],
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.aws_it_client.set_create_auth(True)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertIn("token", new_secret_dict)

        new_token = new_secret_dict["token"]
        self.assert_token_is_scoped_to_primary_org(token=new_token)

    def test_retrigger_custom_token_rotation_no_token_create_auth_enabled(self):
        """
        Successful re-rotation for custom token.
        """
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_CUSTOM,
            permissions=["read-orgs"],
        )
        # Set the user secret using the new all access token
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.aws_it_client.set_create_auth(True)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertIn("token", new_secret_dict)

        new_token = new_secret_dict["token"]
        self.assert_token_is_scoped_to_primary_org(token=new_token)

        # Rotate newly-created custom token
        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.set_user_secret_dict(
            token_type=self.influxdb_it_client.TOKEN_TYPE_CUSTOM,
            token=new_token,
            permissions=["read-orgs"],
        )
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)

        new_token = self.aws_it_client.get_user_secret_dict()["token"]
        self.assert_token_is_scoped_to_primary_org(token=new_token)

    def test_username_and_password_rotation_non_existent_user_create_auth_enabled(self):
        """
        Successful rotation for non-existent-user with create auth enabled.
        """
        self.set_user_secret_dict(
            username=self.influxdb_it_client.NON_EXISTENT_USERNAME
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        self.aws_it_client.set_create_auth(True)
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_secret_dict = self.aws_it_client.get_user_secret_dict()
        self.assertIn("password", new_secret_dict)

    def test_username_and_password_rotation(self):
        """
        Successful rotation for existing user with create auth disabled.
        """
        self.set_user_secret_dict(
            username=self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME,
            password=self.influxdb_it_client.influxdb_admin_password,
        )
        self.aws_it_client.post_user_secret(secret_dict=self.user_secret_dict)
        old_password = self.user_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_user_secret(), True)
        new_password = self.aws_it_client.get_user_secret_dict()["password"]
        self.assertNotEqual(old_password, new_password)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Multi-user rotation Lambda integration tests"
    )
    parser.add_argument(
        "--region",
        help="The name of the AWS region to use for integration testing. "
        "If not provided, will default to the AWS_DEFAULT_REGION environment variable.",
        required=False,
    )
    parser.add_argument(
        "--cleanup",
        help="Whether to teardown all testing resources, including the "
        "Timestream for InfluxDB instance and secrets.",
        required=False,
        action="store_true",
    )
    args, unknown = parser.parse_known_args()
    if args.region is not None:
        aws_region_name = args.region
        os.environ["AWS_DEFAULT_REGION"] = aws_region_name
    else:
        try:
            aws_region_name = os.environ["AWS_DEFAULT_REGION"]
        except KeyError:
            logger.error("AWS_DEFAULT_REGION environment variable not set. Exiting.")
            exit(1)
    cleanup = args.cleanup

    # unittest.main() also parses sys.argv and won't recognize --cleanup or --region
    filtered_argv = []
    for i in range(len(sys.argv)):
        if (
            sys.argv[i] != "--cleanup"
            and sys.argv[i] != "--region"
            and (i == 0 or sys.argv[i - 1] != "--region")
        ):
            filtered_argv.append(sys.argv[i])
    sys.argv = filtered_argv
    my_base = BaseTestCases()
    unittest.main(exit=False)
