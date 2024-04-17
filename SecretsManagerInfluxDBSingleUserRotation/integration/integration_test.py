# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import argparse
import os
import sys
import unittest

from aws_integration_test_client import AWSIntegrationTestClient
from influxdb_integration_test_client import InfluxDBIntegrationTestClient
from integration_test_utils import logger

aws_region_name = ""

# Whether to delete all AWS resources after testing
cleanup = False


class BaseTestCases:
    class BaseTestCase(unittest.TestCase):
        admin_secret_dict = {}
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
            Overrides unittest.TestCase.setUp, called before each test runs.
            """
            assert self.aws_it_client is not None
            assert self.influxdb_it_client is not None
            # Create a new InfluxDB token and initialize self.admin_secret_dict to default values
            self.influxdb_it_client.create_current_auth()
            self.set_admin_secret_dict(
                token=self.influxdb_it_client.current_auth.token,
            )
            # Stop a rotation if it was left in progress
            self.aws_it_client.cancel_rotate_admin_secret()

        def set_admin_secret_dict(
            self,
            db_identifier=None,
            org_name=None,
            token=None,
            username=None,
            password=None,
        ):
            """
            Sets internal secret dict.
            """
            # Mandatory fields
            secret_dict = {
                "engine": self.influxdb_it_client.TIMESTREAM_INFLUXDB_ENGINE,
                "dbIdentifier": db_identifier
                if db_identifier is not None
                else self.influxdb_it_client.influxdb_id,
                "org": org_name
                if org_name is not None
                else self.influxdb_it_client.INFLUXDB_ORG_NAME,
            }
            if token is not None:
                secret_dict["token"] = token
            if username is not None:
                secret_dict["username"] = username
            if password is not None:
                secret_dict["password"] = password
            self.admin_secret_dict = secret_dict

        def tearDown(self):
            """
            Overrides unittest.TestCase.tearDown, called after each test runs.
            """
            if self.aws_it_client is not None:
                # Stop a rotation if it was left in progress
                self.aws_it_client.cancel_rotate_admin_secret()
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
        self.set_admin_secret_dict()
        self.aws_it_client.post_admin_secret(secret_dict=self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_secret_dict = self.aws_it_client.get_admin_secret_dict()
        self.assertNotIn("token", new_secret_dict)

    def test_random_operator_token_rotation(self):
        """
        Failure rotation for random operator token.
        """
        self.set_admin_secret_dict(token="random-token")
        self.aws_it_client.post_admin_secret(secret_dict=self.admin_secret_dict)
        old_token = self.admin_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

    def test_username_and_password_rotation_incorrect_password(self):
        """
        Wrong password set for user fails.
        """
        self.set_admin_secret_dict(
            username=self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME,
            password="this-is-an-incorrect-password",
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_password = self.admin_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

    def test_username_and_password_rotation_no_password(self):
        """
        Failure rotation for admin credentials without password provided.
        """
        self.set_admin_secret_dict(
            username=self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_secret_dict = self.aws_it_client.get_admin_secret_dict()
        self.assertNotIn("password", new_secret_dict)

    def test_username_and_password_rotation_non_existent_user(self):
        """
        Non-existent-user set fails.
        """
        self.set_admin_secret_dict(
            username=self.influxdb_it_client.NON_EXISTENT_USERNAME, password="rosebud"
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_password = self.admin_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

    def test_operator_token_rotation_missing_mandatory_fields(self):
        """
        Failures for token rotation without mandatory secret fields.

        Mandatory secret fields are "engine," "org," "dbIdentifier," and "token."
        """
        self.admin_secret_dict.pop("engine", None)
        self.admin_secret_dict.pop("dbIdentifier", None)
        self.admin_secret_dict.pop("org", None)
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_token = self.admin_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        self.admin_secret_dict["engine"] = (
            self.influxdb_it_client.TIMESTREAM_INFLUXDB_ENGINE
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        self.admin_secret_dict["org"] = self.influxdb_it_client.INFLUXDB_ORG_NAME
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertEqual(old_token, new_token)

        # Now, expect success
        self.admin_secret_dict["dbIdentifier"] = self.influxdb_it_client.influxdb_id
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)

    def test_username_and_password_rotation_missing_mandatory_fields(self):
        """
        Failures for credential rotation without mandatory secret fields.

        Mandatory secret fields are "engine," "dbIdentifier," "username," and "password."
        """
        self.set_admin_secret_dict(
            password=self.influxdb_it_client.influxdb_admin_password
        )
        self.admin_secret_dict.pop("engine", None)
        self.admin_secret_dict.pop("dbIdentifier", None)
        self.admin_secret_dict.pop("username", None)
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_password = self.admin_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

        self.admin_secret_dict["engine"] = (
            self.influxdb_it_client.TIMESTREAM_INFLUXDB_ENGINE
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

        self.admin_secret_dict["dbIdentifier"] = self.influxdb_it_client.influxdb_id
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), False)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertEqual(old_password, new_password)

        self.admin_secret_dict["username"] = (
            self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertNotEqual(old_password, new_password)

    def test_operator_token_rotation(self):
        """
        Successful rotation for operator token with token provided.
        """
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_token = self.admin_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)

    def test_retrigger_operator_token_rotation(self):
        """
        Successful re-rotation for operator token
        """
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_token = self.admin_secret_dict["token"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)
        old_token = new_token

        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_token = self.aws_it_client.get_admin_secret_dict()["token"]
        self.assertNotEqual(old_token, new_token)

    def test_username_and_password_rotation(self):
        """
        Successful rotation for admin credentials with credentials provided.
        """
        self.set_admin_secret_dict(
            username=self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME,
            password=self.influxdb_it_client.influxdb_admin_password,
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_password = self.admin_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertNotEqual(old_password, new_password)

    def test_retrigger_username_and_password_rotation(self):
        """
        Successful re-rotation for admin credentials with credentials provided.
        """
        self.set_admin_secret_dict(
            username=self.influxdb_it_client.INFLUXDB_ADMIN_USERNAME,
            password=self.influxdb_it_client.influxdb_admin_password,
        )
        self.aws_it_client.post_admin_secret(self.admin_secret_dict)
        old_password = self.admin_secret_dict["password"]
        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertNotEqual(old_password, new_password)
        old_password = new_password

        self.assertEqual(self.aws_it_client.rotate_admin_secret(), True)
        new_password = self.aws_it_client.get_admin_secret_dict()["password"]
        self.assertNotEqual(old_password, new_password)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Single-user rotation Lambda integration tests"
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
    unittest.main(exit=False)
