# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from contextlib import contextmanager
import json
import time
import os
import sys

import boto3
from botocore.exceptions import ClientError
import influxdb_client
from influxdb_client.rest import ApiException
from integration_test_utils import random_string, logger

sys.path.insert(1, os.path.realpath(os.path.pardir))
from lambda_function import create_operator_token_perms


class InfluxDBIntegrationTestClient:
    SLEEP_SECONDS = 15
    MAXIMUM_WAIT_SECONDS = 1200  # 20 minutes
    TIMESTREAM_INFLUXDB_ENGINE = "timestream-influxdb"
    TOKEN_TYPE_ALL_ACCESS = "allAccess"
    TOKEN_TYPE_CUSTOM = "custom"
    TOKEN_TYPE_OPERATOR = "operator"
    NON_EXISTENT_USERNAME = "gregstopher"
    VPC_TAG_KEY = "tmp-influxdb-integration-test-vpc"
    INFLUXDB_INSTANCE_TAG_KEY = "tmp-influxdb-integration-test-db"
    INFLUXDB_INSTANCE_TAG_VALUE = "multi-user-rotation-integration-db"
    INFLUXDB_ADMIN_USERNAME = "admin"
    INFLUXDB_ORG_NAME = "org"
    INFLUXDB_SECONDARY_ORG_NAME = "secondary-org"
    INFLUXDB_BUCKET = "test-bucket"
    INFLUXDB_TYPE = "db.influx.medium"
    _region_name: str
    _boto3_session = None
    _resource_client = None
    _timestream_influxdb_client = None
    _secrets_client = None
    _ec2 = None
    _ec2_client = None

    # influxdb_client must be accessed and closed by integration_test
    # because influxdb_client.__del__ does an import during program shutdown
    # which causes alarming logs
    influxdb_client = None
    current_auth = None
    static_operator_token: str = ""
    influxdb_admin_id: str = ""
    influxdb_admin_password: str = ""
    influxdb_arn: str = ""
    influxdb_endpoint: str = ""
    influxdb_id: str = ""
    influxdb_org_id: str = ""
    influxdb_secondary_org_id: str = ""
    vpc_id: str = ""

    def __init__(self, region_name) -> None:
        self._region_name = region_name
        self._boto3_session = boto3.Session(region_name=self._region_name)
        self._resource_client = self._boto3_session.client("resourcegroupstaggingapi")
        self._timestream_influxdb_client = self._boto3_session.client(
            "timestream-influxdb"
        )
        self._secrets_client = self._boto3_session.client("secretsmanager")
        self._ec2 = self._boto3_session.resource("ec2", region_name=self._region_name)
        self._ec2_client = self._ec2.meta.client

    def get_influxdb_resources_by_tag(self, tag_key, tag_value):
        """
        Returns Timestream for InfluxDB resources using its tag key and tag value.

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

    def init_timestream_for_influxdb(self):
        """
        Initializes Timestream for InfluxDB, creating a Timestream for InfluxDB instance
            if needed, along with its VPC.

        :return: None
        """
        # Test whether instance already exists
        existing_test_dbs = self.get_influxdb_resources_by_tag(
            tag_key=self.INFLUXDB_INSTANCE_TAG_KEY,
            tag_value=self.INFLUXDB_INSTANCE_TAG_VALUE,
        )
        if len(existing_test_dbs) > 0:
            logger.info("Existing Timestream for InfluxDB instance found")
            self.influxdb_arn = existing_test_dbs[0]["ResourceARN"]
            self.use_existing_timestream_influxdb_instance()
        # Test instance does not exist, create it
        else:
            logger.info("No existing Timestream for InfluxDB instance could be found")
            self.create_new_timestream_influxdb_instance()

    def use_existing_timestream_influxdb_instance(self):
        """
        Populates AWS values associated with the Timestream for InfluxDB test
            instance, such as its ID, endpoint, stored password, and ARN.

        :return: None
        """
        try:
            instances = self._timestream_influxdb_client.list_db_instances()

            for instance in instances["items"]:
                if instance["arn"] == self.influxdb_arn:
                    self.influxdb_id = instance["id"]
            while self.influxdb_id == "" and instances["nextToken"] != "":
                for instance in instances["items"]:
                    if instance["arn"] == self.influxdb_arn:
                        self.influxdb_id = instance["id"]
                instances = self._timestream_influxdb_client.list_db_instances(
                    nextToken=instances["nextToken"]
                )
            if self.influxdb_id == "":
                raise ValueError(
                    "ERROR: Metadata for existing Timestream for InfluxDB instance could not be retrieved"
                )
            instance_secret_arn = self._timestream_influxdb_client.get_db_instance(
                identifier=self.influxdb_id
            )["influxAuthParametersSecretArn"]
            self.influxdb_admin_password = json.loads(
                self._secrets_client.get_secret_value(SecretId=instance_secret_arn)[
                    "SecretString"
                ]
            )["password"]

            self.influxdb_endpoint = self._timestream_influxdb_client.get_db_instance(
                identifier=self.influxdb_id
            )["endpoint"]

            self.get_default_influxdb_metadata()
            # Get secondary org ID
            orgs = self.influxdb_client.organizations_api().find_organizations(
                org=self.INFLUXDB_SECONDARY_ORG_NAME
            )
            if len(orgs) < 1:
                raise ValueError("Secondary org could not be found")
            self.influxdb_secondary_org_id = orgs[0].id
        except Exception as error:
            logger.error(repr(error))
            raise

    def create_new_timestream_influxdb_instance(self):
        """
        Creates a new test Timestream for InfluxDB instance, including its
            VPC.

        :return: None
        """
        try:
            vpc_create_response = self._ec2_client.create_vpc(
                CidrBlock="10.0.0.0/16", AmazonProvidedIpv6CidrBlock=False
            )
            vpc_id = vpc_create_response["Vpc"]["VpcId"]
            self._ec2_client.create_tags(
                Resources=[vpc_id],
                Tags=[
                    {"Key": "Name", "Value": "influxdb-integration-vpc"},
                    {
                        "Key": self.VPC_TAG_KEY,
                        "Value": self.INFLUXDB_INSTANCE_TAG_VALUE,  # Tag to help deletion later
                    },
                ],
            )
            logger.info(f"Created VPC with ID {vpc_id}")
            self._ec2_client.modify_vpc_attribute(
                VpcId=vpc_id,
                EnableDnsSupport={"Value": True},
            )
            self._ec2_client.modify_vpc_attribute(
                VpcId=vpc_id, EnableDnsHostnames={"Value": True}
            )
            ig_create_response = self._ec2_client.create_internet_gateway()
            ig_id = ig_create_response["InternetGateway"]["InternetGatewayId"]
            self._ec2_client.attach_internet_gateway(
                InternetGatewayId=ig_id, VpcId=vpc_id
            )
            subnet_response = self._ec2_client.create_subnet(
                VpcId=vpc_id,
                CidrBlock="10.0.0.0/24",
                AvailabilityZone=f"{self._region_name}a",
            )
            subnet_id = subnet_response["Subnet"]["SubnetId"]
            route_table_create_response = self._ec2_client.create_route_table(
                VpcId=vpc_id
            )
            self._ec2_client.create_route(
                RouteTableId=route_table_create_response["RouteTable"]["RouteTableId"],
                DestinationCidrBlock="0.0.0.0/0",
                GatewayId=ig_id,
            )
            self._ec2_client.associate_route_table(
                RouteTableId=route_table_create_response["RouteTable"]["RouteTableId"],
                SubnetId=subnet_id,
            )
            security_group_response = self._ec2_client.create_security_group(
                Description=f"VPC security group for {self.INFLUXDB_INSTANCE_TAG_VALUE}",
                GroupName=self.INFLUXDB_INSTANCE_TAG_VALUE,
                VpcId=vpc_id,
            )
            security_group_id = security_group_response["GroupId"]
            self._ec2_client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 8086,
                        "ToPort": 8086,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )
        except Exception:
            logger.error("Failed to create VPC and VPC dependencies")
            raise

        self.influxdb_admin_password = random_string(20)

        logger.info("Creating new Timestream for InfluxDB instance")
        try:
            instance = self._timestream_influxdb_client.create_db_instance(
                name=self.INFLUXDB_INSTANCE_TAG_VALUE + random_string(3),
                username=self.INFLUXDB_ADMIN_USERNAME,
                password=self.influxdb_admin_password,
                organization=self.INFLUXDB_ORG_NAME,
                bucket=self.INFLUXDB_BUCKET,
                dbInstanceType=self.INFLUXDB_TYPE,
                vpcSubnetIds=[subnet_id],
                vpcSecurityGroupIds=[security_group_id],
                publiclyAccessible=True,
                dbStorageType="InfluxIOIncludedT1",
                allocatedStorage=20,
                deploymentType="SINGLE_AZ",
                tags={self.INFLUXDB_INSTANCE_TAG_KEY: self.INFLUXDB_INSTANCE_TAG_VALUE},
            )
        except Exception:
            logger.error("Failed to create Timestream for InfluxDB instance")
            raise

        self.influxdb_arn = instance["arn"]

        self.influxdb_id = instance["id"]

        try:
            instance = self._timestream_influxdb_client.get_db_instance(
                identifier=self.influxdb_id
            )
        except Exception:
            logger.error("Failed to get new Timestream for InfluxDB instance")
            raise

        elapsed_time = 0
        while (
            instance["status"] == "CREATING"
            and elapsed_time < self.MAXIMUM_WAIT_SECONDS
        ):
            time.sleep(self.SLEEP_SECONDS)
            elapsed_time += self.SLEEP_SECONDS
            instance = self._timestream_influxdb_client.get_db_instance(
                identifier=self.influxdb_id
            )
            logger.info(f"Creation status: {instance['status']}")
        if (
            elapsed_time >= self.MAXIMUM_WAIT_SECONDS
            and instance["status"] != "AVAILABLE"
        ):
            raise ValueError("A Timestream for InfluxDB instance could not be created")
        else:
            logger.info(
                f"New Timestream for InfluxDB instance created with endpoint {instance['endpoint']}, status: {instance['status']}"
            )
            # Using an instance too soon can cause issues
            time.sleep(30)
            instance = self._timestream_influxdb_client.get_db_instance(
                identifier=self.influxdb_id
            )

        logger.info("Getting endpoint")
        self.influxdb_endpoint = instance["endpoint"]
        self.get_default_influxdb_metadata()
        logger.info("Creating secondary org")
        secondary_org = self.influxdb_client.organizations_api().create_organization(
            name=self.INFLUXDB_SECONDARY_ORG_NAME
        )
        self.influxdb_secondary_org_id = secondary_org.id

    def get_default_influxdb_metadata(self):
        """
        Gets default Timestream for InfluxDB metadata, such as admin user ID,
            operator token, and primary org ID, using the InfluxDB client.

        :return: None
        """
        try:
            self.influxdb_client = influxdb_client.InfluxDBClient(
                url=f"https://{self.influxdb_endpoint}:8086",
                username=self.INFLUXDB_ADMIN_USERNAME,
                password=self.influxdb_admin_password,
                org=self.INFLUXDB_ORG_NAME,
            )

            users = self.influxdb_client.users_api().find_users(
                name=self.INFLUXDB_ADMIN_USERNAME
            )
            if len(users.users) < 1:
                raise ValueError("Admin user ID could not be found")
            self.influxdb_admin_id = users.users[0].id

            orgs = self.influxdb_client.organizations_api().find_organizations(
                org=self.INFLUXDB_ORG_NAME
            )
            if len(orgs) < 1:
                raise ValueError("Primary org could not be found")
            self.influxdb_org_id = orgs[0].id

            auths = self.influxdb_client.authorizations_api().find_authorizations(
                org=self.INFLUXDB_ORG_NAME
            )

            for auth in auths:
                # The first token, created when the instance is first created,
                # will have the following description
                if auth.description == f"{self.INFLUXDB_ADMIN_USERNAME}'s Token":
                    self.static_operator_token = auth.token
            if self.static_operator_token == "":
                raise ValueError(
                    "The static operator token could not be retrieved from the Timestream for InfluxDB instance"
                )
        except Exception as error:
            logger.error(repr(error))
            raise

    def create_current_auth(self, token_perms=None):
        """
        Creates a new token in Timestream for InfluxDB and sets
            InfluxDBIntegrationTestClient.current_auth to this new authorization.

        :param list[influxdb_client.Permission]: A list of Permissions to use to create
            the authorization.
        :return: None
        """
        if token_perms is None:
            token_perms = create_operator_token_perms()
        try:
            self.current_auth = (
                self.influxdb_client.authorizations_api().create_authorization(
                    org_id=self.influxdb_org_id, permissions=token_perms
                )
            )
        except Exception as error:
            logger.error(repr(error))
            logger.error("Failed to create new Timestream for InfluxDB token")

    def teardown(self):
        """
        Deletes all Timestream for InfluxDB resources, including the Timestream for InfluxDB
            instance and its VPC.

        :return: None
        """
        self.delete_influxdb_instance()
        # Delete test VPCs as deleting a Timestream for InfluxDB instance won't delete its VPCs
        # VPCs can only be deleted after the instance has been deleted
        existing_test_vpcs = self.get_influxdb_resources_by_tag(
            tag_key=self.VPC_TAG_KEY, tag_value=self.INFLUXDB_INSTANCE_TAG_VALUE
        )
        if len(existing_test_vpcs) > 0:
            for vpc in existing_test_vpcs:
                vpc_id = vpc["ResourceARN"].split("/")[-1]
                self.delete_vpc_and_dependencies(vpc_id=vpc_id)

    def delete_influxdb_instance(self):
        """
        Deletes the test Timestream for InfluxDB instance. This method will wait
            for the instance to finish deleting.

        :return: None
        """
        logger.info(f"Deleting Timestream for InfluxDB instance {self.influxdb_id}")
        try:
            self._timestream_influxdb_client.delete_db_instance(
                identifier=self.influxdb_id
            )
        except Exception:
            raise
        try:
            instance = self._timestream_influxdb_client.get_db_instance(
                identifier=self.influxdb_id
            )
            elapsed_time = 0
            while (
                instance["status"] == "DELETING"
                and elapsed_time < self.MAXIMUM_WAIT_SECONDS
            ):
                time.sleep(self.SLEEP_SECONDS)
                elapsed_time += self.SLEEP_SECONDS
                instance = self._timestream_influxdb_client.get_db_instance(
                    identifier=self.influxdb_id
                )
                logger.info(f"Deletion status: {instance['status']}")
            if (
                elapsed_time >= self.MAXIMUM_WAIT_SECONDS
                and instance["status"] == "DELETING"
            ):
                logger.error(
                    f"Failed to delete Timestream for InfluxDB instance {self.influxdb_id}"
                )
        # get_db_instance will throw a ResourceNotFoundException when the instance is finished deleting
        except self._timestream_influxdb_client.exceptions.ResourceNotFoundException:
            logger.info("Timestream for InfluxDB instance deleted")

    def delete_vpc_and_dependencies(self, vpc_id):
        """
        Deletes the Timestream for InfluxDB VPC and all of its associated resources.

        :return: None
        """
        try:
            vpc = self._ec2.Vpc(vpc_id)

            # Delete transit gateway attachments
            for attachment in self._ec2_client.describe_transit_gateway_attachments()[
                "TransitGatewayAttachments"
            ]:
                if attachment["ResourceId"] == vpc_id:
                    self._ec2_client.delete_transit_gateway_vpc_attachment(
                        TransitGatewayAttachmentId=attachment[
                            "TransitGatewayAttachmentId"
                        ]
                    )

            # Delete NAT gateways
            filters = [{"Name": "vpc-id", "Values": [vpc_id]}]
            for nat_gateway in self._ec2_client.describe_nat_gateways(Filters=filters)[
                "NatGateways"
            ]:
                self._ec2_client.delete_nat_gateway(
                    NatGatewayId=nat_gateway["NatGatewayId"]
                )

            # Detach default DHCP options
            dhcp_default_options = self._ec2.DhcpOptions("default")
            if dhcp_default_options:
                dhcp_default_options.associate_with_vpc(VpcId=vpc_id)

            # Delete gateways
            for gateway in vpc.internet_gateways.all():
                vpc.detach_internet_gateway(InternetGatewayId=gateway.id)
                gateway.delete()

            # Delete any VPC peering connections
            request_peers = self._ec2_client.describe_vpc_peering_connections(
                Filters=[{"Name": "requester-vpc-info.vpc-id", "Values": [vpc_id]}]
            )
            accept_peers = self._ec2_client.describe_vpc_peering_connections(
                Filters=[{"Name": "accepter-vpc-info.vpc-id", "Values": [vpc_id]}]
            )
            for peer in request_peers["VpcPeeringConnections"]:
                self._ec2.VpcPeeringConnection(peer["VpcPeeringConnectionId"]).delete()
            for peer in accept_peers["VpcPeeringConnections"]:
                self._ec2.VpcPeeringConnection(peer["VpcPeeringConnectionId"]).delete()

            # Delete endpoints
            endpoints = self._ec2_client.describe_vpc_endpoints(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )
            for endpoint in endpoints["VpcEndpoints"]:
                self._ec2_client.delete_vpc_endpoints(
                    VpcEndpointIds=endpoint["VpcEndpointId"]
                )

            # Delete security groups
            for security_group in vpc.security_groups.all():
                if security_group.group_name != "default":
                    security_group.delete()

            # Delete non-default network ACLs
            for net_acl in vpc.network_acls.all():
                if not net_acl.is_default:
                    net_acl.delete()

            try:
                # Delete route tables and route table associations
                filters = [{"Name": "vpc-id", "Values": [vpc_id]}]
                route_tables = self._ec2_client.describe_route_tables(Filters=filters)[
                    "RouteTables"
                ]
                for route_table in route_tables:
                    for route in route_table["Routes"]:
                        if route["Origin"] == "CreateRoute":
                            self._ec2_client.delete_route(
                                RouteTableId=route_table["RouteTableId"],
                                DestinationCidrBlock=route["DestinationCidrBlock"],
                            )
                        for association in route_table["Associations"]:
                            if not association["Main"]:
                                self._ec2_client.disassociate_route_table(
                                    AssociationId=association["RouteTableAssociationId"]
                                )
                                self._ec2_client.delete_route_table(
                                    RouteTableId=route_table["RouteTableId"]
                                )
                for route_table in route_tables:
                    if route_table["Associations"] == []:
                        self._ec2_client.delete_route_table(
                            RouteTableId=route_table["RouteTableId"]
                        )
            except ClientError:
                # An exception will be raised for a route not having a DestinationCidrBlock of 0.0.0.0/0
                # this can be ignored
                pass

            # Delete subnets and network interfaces
            for subnet in vpc.subnets.all():
                for interface in subnet.network_interfaces.all():
                    interface.delete()
                for instance in subnet.instances.all():
                    filters = [{"Name": "instance-id", "Values": [instance.id]}]
                    eips = self._ec2_client.describe_addresses(Filters=filters)[
                        "Addresses"
                    ]
                    for eip in eips:
                        self._ec2_client.disassociate_address(
                            AssociationId=eip["AssociationId"]
                        )
                        self._ec2_client.release_address(
                            AllocationId=eip["AllocationId"]
                        )
                subnet.delete()

            # Delete instances
            filters = [
                {"Name": "instance-state-name", "Values": ["running"]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
            ec2_instances = self._ec2_client.describe_instances(Filters=filters)
            instance_ids = []
            for reservation in ec2_instances["Reservations"]:
                instance_ids += [
                    instance["InstanceId"] for instance in reservation["Instances"]
                ]
            if len(instance_ids) > 0:
                waiter = self._ec2_client.get_waiter("instance_terminated")
                self._ec2_client.terminate_instances(InstanceIds=instance_ids)
                waiter.wait(InstanceIds=instance_ids)

            # Delete VPC
            self._ec2_client.delete_vpc(VpcId=vpc_id)
        except Exception as error:
            logger.error(repr(error))
            logger.error("Failed to delete VPC and dependencies")

    def delete_non_admin_tokens(self):
        """
        Deletes all tokens in the Timestream for InfluxDB instance that does not
            match the current static operator token.

        :return: None
        """
        try:
            auths = self.influxdb_client.authorizations_api().find_authorizations(
                org_id=self.influxdb_org_id
            )
            for auth in auths:
                if auth.token != self.static_operator_token:
                    self.influxdb_client.authorizations_api().delete_authorization(auth)
        except ApiException as error:
            logger.error(repr(error))

    def reset_admin_password(self):
        """
        Resets the admin password in Timestream for InfluxDB to the password
            set in init_timestream_for_influxdb.

        :return: None
        """
        self.influxdb_client.users_api().update_password(
            user=self.influxdb_admin_id, password=self.influxdb_admin_password
        )

    def reset_non_existent_user(self):
        """
        Ensures the non-existent user, needed for testing, remains non-existent by
            deleting this user if it exists in the Timestream for InfluxDB instance.

        :return: None
        """
        try:
            users = (
                self.influxdb_client.users_api()
                .find_users(name=self.NON_EXISTENT_USERNAME)
                .users
            )
            if users is not None:
                for user in users:
                    self.influxdb_client.users_api().delete_user(user)
        except ApiException:
            pass

    def get_primary_org(self, token):
        """
        Gets the primary org from Timestream for InfluxDB.

        :param str token: The token to use to get the org.
        :return: A list of influxdb_client.domain.organization.Organization objects
            with the same org ID as the primary org.
        """
        with self.get_connection_using_token(token) as conn:
            return self.get_orgs(conn, self.influxdb_org_id)

    def get_secondary_org(self, token):
        """
        Gets the secondary org from Timestream for InfluxDB.

        :param str token: The token to use to get the org.
        :return: A list of influxdb_client.domain.organization.Organization objects
            with the same org ID as the secondary org.
        """
        with self.get_connection_using_token(token) as conn:
            return self.get_orgs(conn, self.influxdb_secondary_org_id)

    def get_orgs(self, test_influxdb_client, org_id):
        """
        Gets orgs using test_influxdb_client with org ID matching org_id.

        :param influxdb_client.InfluxDBClient test_influxdb_client:
            The InfluxDB client to use to get the orgs.
        :param str org_id: The ID of the org to get.
        :return: A list of influxdb_client.domain.organization.Organization objects
            with the same org ID as org_id.
        """
        return test_influxdb_client.organizations_api().find_organizations(
            org_id=org_id
        )

    @contextmanager
    def get_connection_using_token(self, token):
        """
        Creates a new InfluxDBClient using the given token.

        :param str token: The InfluxDB token to use to create an InfluxDB client.
        :return: An InfluxDB client connection.
        """
        conn = None
        try:
            conn = influxdb_client.InfluxDBClient(
                url=f"https://{self.influxdb_endpoint}:8086",
                token=token,
                debug=False,
                verify_ssl=True,
            )
            yield conn
        except Exception as err:
            raise ValueError("Error getting connection") from err
        finally:
            if conn is not None:
                conn.close()
