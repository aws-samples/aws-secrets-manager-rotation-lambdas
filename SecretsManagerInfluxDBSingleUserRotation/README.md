# Amazon InfluxDB Single User Rotator

## Getting Started
The InfluxDB Single-User Rotator rotates a user's authorization token or credentials using the AWS Secrets Manager. The Single-user rotator operates by using the user's authentication token or credentials to rotate their token or credentials with new permission identical equivalents. The user token performing the rotation must have the permissions to perform the rotation. For token rotation the type of the token could be an `operator` or `allAccess` token to successfully complete rotation.

### InfluxDB Single-user Token Rotation State Diagram
The InfluxDB Single-user Token Rotation State Diagram illustrates how a secret authenticates the rotation of their own user or token with each successful step provided by the `Secrets Manager`.

```mermaid
stateDiagram-v2
direction LR
    createSecret --> testSecret: Success
    testSecret --> finishSecret: Success

    state "Step: createSecret" as createSecret
    state createSecret {
        Secretsmanager1: Secrets Manager
        state1token: old token
        state1oldtoken: old token
        state1newtoken: new token

        Secretsmanager1 --> State1UserRef1 : step - createSecret
        State1UserRef1 --> State1UserRef2 : Creates new user token

        state "User" as State1UserRef1 {
            state1token
        }
        state "User" as State1UserRef2 {
            state1oldtoken
            state1newtoken
        }
    }

    state "Step: testSecret" as testSecret
    state testSecret {
        Secretsmanager2: Secrets Manager
        state2token: old token
        state2oldtoken: old token
        state2newtoken1: new token
        state2newtoken2: new token

        Secretsmanager2 --> State2UserRef1 : step - testSecret
        State2UserRef1 --> User2 : Validates new vs old token permissions

        state "User" as State2UserRef1 {
            state2token
            state2newtoken1
        }
        state "User" as User2 {
            state2oldtoken
            state2newtoken2
        }
    }

    state "Step: finishSecret" as finishSecret
    state finishSecret {
        Secretsmanager3: Secrets Manager
        state3token: old token
        state3newtoken1: new token
        state3newtoken2: new token

        Secretsmanager3 --> State3UserRef1 : step - finishSecret
        State3UserRef1 --> User3 : Deletes old token

        state "User" as State3UserRef1 {
            state3token
            state3newtoken1
        }
        state "User" as User3 {
            state3newtoken2
        }
    }

    classDef green fill:#32cd32
    classDef orange fill:#f96
    classDef yellow fill:#eeff1b
    class state1newtoken orange
    class state2newtoken2, state2oldtoken yellow
    class state3newtoken2 green


```

## Permissions
The `InfluxDB Single-user Rotation Lambda` rotates an existing user or token with the same permissions that are defined for the user or token in the DB instance. This is to avoid any scenarios where privilege escalation could occur during the rotation.

## Create Secret
1. Open the AWS console
- Navigate to `Secrets Manager`
- Click `Store a new secret`
- Select `Other type of secret`
- Click on `Plaintext` under `Key/value pairs`
- Fill in one of the following options in the text box:

Token Credentials (for rotating operator token)
```
{
    "engine": "timestream-influxdb",            // mandatory engine name
    "org": "string",                            // mandatory organization to associate token with
    "dbIdentifier": "string",                   // mandatory DB instance identifier
    "token": "string"                           // mandatory token value
}
```

Username and Password Credentials (for rotating admin user password)
```
{
    "engine": "timestream-influxdb",            // mandatory engine name
    "dbIdentifier": "string",                   // mandatory DB instance identifier
    "username": "string",                       // mandatory username for rotating user
    "password": "string"                        // mandatory current password for rotating user
}
```
- Click `Next`
- Enter a name for the secret of your choosing
- Click `Next`
- Click `Next` again as we will configure the rotation after we deploy the lambda
- Click `Store`

## Deploy Lambda
1. Execute script with the following command (Requires pip3 installed)
- If you are using macOS or Linux, execute the following commands
  - `./build_deployment.sh`_(to build deployable lambda function package from the source code)_
  - Execute the following command to add execution permissions to your deployment package
  - `sudo chmod +x influxdb-token-rotation-lambda.zip`
- If you are using Windows, execute the following command
  - `./build_deployment.ps1`_(to build deployable lambda function package from the source code)_

2. Open the AWS console
- Navigate to `Lambda`
- Click `Create function`
- Enter a function name of your choosing
- Select `Python 3.12` for the Runtime
- Click `Create function`

3. Upload the deployment package
- Click on `Upload from` and select `.zip` file
- Click `Upload` and select the `influxdb-token-rotation-lambda.zip` deployment package
- Click `Save`

4. Configure environment variables for the lambda function
- Click on `Configuration`
- Click on `Environment Variables` and click on `Edit`
- Click on `Add environment variable`
- Enter `SECRETS_MANAGER_ENDPOINT` for the key value
- Enter `https://secretsmanager.<region>.amazonaws.com` and replace `<region>` appropriately (Must be same as `Secrets Manager`)
- Click `Save`

5. Configure lambda role
- Click on `Permissions`
- Under `Execution role` click on the link to the lambda role
- Under `Permissions policies` click `Add permissions` and `Create inline policy`
- Click on `JSON` and replace the json in the text editor with the following:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:DescribeSecret",
                "secretsmanager:GetSecretValue",
                "secretsmanager:PutSecretValue",
                "secretsmanager:UpdateSecretVersionStage"
            ],
            "Resource": "<user_secret_arn>"
        },
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetRandomPassword"
            ],
            "Resource": "*"
        },
        {
            "Action": [
                "timestream-influxdb:GetDbInstance"
            ],
            "Resource": "arn:aws:timestream-influxdb:<region>:<account_id>:db-instance/<db_instance_id>",
            "Effect": "Allow"
        }
    ]
}
```
- Replace `<region>`, `<account_id>`, `<db_instance_id>`, and `<user_secret_arn>` appropriately
- Click `Next`
- Enter a `Policy name` of your choosing and click `Create policy`

6. Configure invoke lambda permissions for the lambda function
- Navigate back to the lambda function `Permissions` section
- Under `Resource-based policy statements` click `Add permissions`
- Click on `AWS service`
- Select `Secrets Manager` under `Service`
- Enter a `Statement ID` of your choosing
- Select `Lambda:InvokeFunction` under `Action`
- Click `Save`

7. Configure lambda function timeout
- Navigate to the lambda function `General configuration` section
- Under `General configuration` click `Edit`
- Set the `Timeout` value to 1 minute
- Click `Save`

## Configure Token Rotation
1. Open the AWS console
- Navigate to `Secrets Manager`
- Select the secret that was previously created
- Click `Rotation` and then `Edit rotation`
- Click on `Automatic rotation`
- Fill in the rotation schedule of your choosing
- Under `Rotation function` select the lambda function we previously deployed
- Ensure the checkbox to rotate immediately when stored is selected
- Click `Save`

## Verify
1. In the secret that we created navigate to the `Overview` section
- Click `Retrieve secret value`
- If everything went correctly you should see a new token value under `influxdb-user-token`
- If the value for `influxdb-user-token` has not changed, see section [Viewing CloudWatch Logs](#viewing-cloudwatch-logs) for troubleshooting

## Viewing CloudWatch Logs
1. Navigate to `Lambda`
- Click on the function created for rotating your `InfluxDB` token
- Click on `Monitor`
- Click on `View CloudWatch logs`
- Click on the latest log stream under `Log streams`
- Look for any `Error` or `Info` logs that can help determine the reason for failure to rotate the token


## Adding Rotation Lambda to same VPC as Timestream for InfluxDB
**Note** - This is not required, but is a configuration option for users requiring the `InfluxDB Rotation Lambda` to run on the same `VPC` as their `Timestream for InfluxDB` Instance.

1. Adding the `InfuxDB Rotation Lambda` to a `VPC` will require the addition of a `NAT Gateway`
- We will create three `Subnets`(One for each `availability zone`) pointing to one `Route table` that routes to the `NAT Gateway`
- Your `Timestream for InfluxDB` instance should already have a `VPC` with a `Subnet` and `Route Table` to an `Internet Gateway`
- If your `VPC` already has a `NAT Gateway` with appropriate `Subnet` and `Route Tables`, you can skip to step `#5`

<br>

2. Create a `NAT Gateway`
- If you already have a `NAT Gateway`, skip to step `#3`
- Click on `NAT Gateway` in the left side bar
- Click on `Create NAT Gateway`
- Fill in the `Name` of your choosing, and select the `Subnet` to be `lambda-subnet-point-to-ig` that you created earlier
- Select `Public` for `Connectivity type` and click `Allocate elastic IP`
- Click `Create NAT Gateway`

<br>

3. Create a `Route Table` for the `NAT Gateway`
- If you already have a route to a `NAT Gateway`, skip to step `#4`
- Click on `Route tables` in the left side bar
- Click `Create route table`
- Fill in the `Name` portion and select the `VPC`
- Click `Create route`
- Click on `Edit routes` and `Add route`
- Select `0.0.0.0/0` for the `Destination`
- Select `NAT Gateway` for `Target` and fill in the `NAT Gateway` we created earlier
- Click `Save Changes`

<br>

4. Adding `Subnets` for the `Nat Gateway`
- If you already have three `Subnets` for the `NAT Gateway`, skip to step `#5`
- Navigate to `VPC` and select `Subnets` in the left side bar
- Click `Create subnet` and select the `VPC ID` of your `VPC`
- We will create three subnets pointing to the `NAT Gateway`, each incrementing the second to last byte of the `IPv4 subnet CIDR block` address by 16, ensure these addresses don't overlap with already existing `Subnets`
- Each `Subnet` will be in their own `availability zone`
- See the following table for reference, and set the IP's dependent on your `VPC IPv4 CIDR`

<br>

| VPC | CIDR | Name |
| --- | ---- | --- |
| vpc-123abc123abc (ip.of.your.vpc/16) | 123.123.0.0/20  | lambda-subnet-point-to-nat-1 |
| vpc-123abc123abc (ip.of.your.vpc/16) | 123.123.16.0/20 | lambda-subnet-point-to-nat-2 |
| vpc-123abc123abc (ip.of.your.vpc/16) | 123.123.32.0/20 | lambda-subnet-point-to-nat-3 |

- Click on the `Create Subnet` for each `Subnet` in the table

<br>

5. Setup `InfluxDB Rotation Lambda`
- Navigate to `Lambda` and select the `InfluxDB Rotation Lambda`
- Click on `Configuration` and select `VPC` in the left side bar
- Click on `Edit` under `VPC`
- Select the `VPC` of the `Timestream for InfluxDB` instance
- Select the three subnets pointing to the `NAT Gateway`
- Select the default security group
- Click `Save`

<br>

6. Your `InfluxDB Rotation Lambda` should now have internet access
- Below I have listed all required components to the VPC for reference
- Your configuration may look different, but if you have a `Route` from your private `Subnets` to a `NAT Gateway` linking through to the `Internet Gateway`, the lambda function should have internet access

<br>

| VPC | CIDR | Name | Route Table | Network Connection |
| --- | ---- | --- | --- | --- |
| vpc-123abc123abc (ip.of.your.vpc/16) | 123.123.0.0/20  | lambda-subnet-point-to-nat-1 | route-to-nat-gw | NAT Gateway |
| vpc-123abc123abc (ip.of.your.vpc/16) | 123.123.16.0/20 | lambda-subnet-point-to-nat-2 | route-to-nat-gw | NAT Gateway |
| vpc-123abc123abc (ip.of.your.vpc/16) | 123.123.32.0/20 | lambda-subnet-point-to-nat-3 | route-to-nat-gw | NAT Gateway |
| vpc-123abc123abc (ip.of.your.vpc/16) | 123.123.48.0/20 | lambda-subnet-point-to-ig    | route-to-ig     | Internet Gateway |

## VPC Network Configuration Diagram

![image](UML/InfluxDB-Rotation-Lambda-Network-Configuration.png)

## Testing

### Integration Tests

To run the integration tests using the default region defined in the `AWS_DEFAULT_REGION` environment variable, execute the following while your shell is in the `integration` directory:

```shell
python3 integration_test.py
```

If the `AWS_DEFAULT_REGION` environment variable is not set or you wish to use a different region, the `--region <region name>` argument will let you set the region to use.

The integration tests will use `boto3` to create a new Timestream for InfluxDB instance (size medium with 20GB of of storage), a VPC required for the Timestream for InfluxDB instance, a lambda function containing `lambda_function.py` and dependencies, and an admin secret, which will be rotated. The integration tests tags these resources; if resources with these tags already exist, then these existing resources will be used.

In addition to the above-mentioned `--region` argument, the integration tests support inividual test arguments, such as running an individual test with `python3 integration_test.py SecretsTestCase.test_operator_token_rotation`, and the option to delete all tagged integration test resources after testing by using `--cleanup`.

> **NOTE**: The secret created by the IT test should not be deleted via the AWS console, as deletion via the AWS console puts secrets into a pending deletion stage where secrets will still be identified by the integration tests. If you wish to delete the integration test secret manually, without using `--cleanup`, delete it using the AWS CLI with `aws secretsmanager delete-secret --secret-id <secret ID> --force-delete-without-recovery`.
