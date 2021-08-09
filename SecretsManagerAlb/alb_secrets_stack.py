

from aws_cdk import (
  aws_iam                    as iam,
  aws_secretsmanager         as secretsmanager,
  aws_kms                    as kms,
  aws_lambda                 as lfn,
  aws_ec2                    as ec2,
  aws_elasticloadbalancingv2 as elbv2,
  core,
)

import string
import random
import json


class ALBSecretsStack(core.Stack):

  ##
  ## Random secret generator
  ## Same function used in the secret key rotator.
  ##
  def key_generator(self):
    size  = 16
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    key   = ''.join(random.choice(chars) for _ in range(size))
    return key

  def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
    super().__init__(scope, id, **kwargs)



    ##
    ## Initial secrets
    ##
    keys = {
      "key1": self.key_generator(),
      "key2": self.key_generator(),
      "key3": self.key_generator(),
    }


    ##
    ## VPC
    ##
    vpc = ec2.Vpc(self, "TheRoomWhereItHappens",
      cidr                 = "10.99.0.0/16",
      max_azs              = 3,
      enable_dns_hostnames = True,
      enable_dns_support   = True,
      subnet_configuration = [
        ec2.SubnetConfiguration(
          cidr_mask   = 24,
          name        = 'public1',
          subnet_type = ec2.SubnetType.PUBLIC,
        ),
        ec2.SubnetConfiguration(
          cidr_mask   = 24,
          name        = 'public2',
          subnet_type = ec2.SubnetType.PUBLIC,
        )
      ] ## subnet_configuration
    ) ## vpc
    vpc.apply_removal_policy(core.RemovalPolicy.DESTROY)


    ##
    ## Sample CloudFront Distribution
    ##
    alb = elbv2.ApplicationLoadBalancer(self, "sampleAlb",
            vpc=vpc,
            #security_group=sg_alb,
            internet_facing=True)

    tg = elbv2.ApplicationTargetGroup(self, "sampleTg", 
      port=80,
      protocol=elbv2.ApplicationProtocol.HTTP,
      target_group_name="sample",
      target_type=elbv2.TargetType.INSTANCE,
      vpc=vpc)


    alb.connections.allow_from_any_ipv4(ec2.Port.tcp(80), "Internet access ALB 80")
    listener = alb.add_listener("tcp80", port=80, open=True,
      #default_action=elbv2.ListenerAction.forward(target_groups=[tg]),
      default_action=elbv2.ListenerAction.fixed_response(status_code=403, content_type="text/plain", message_body=None),
    )

    ##
    ## ALB -> Listener -> Rules -> 1
    ##   Conditions -> 
    ##      "Field": "http-header",
    ##        "HttpHeaderName": "X-AWS-API-KEY",
    ##
    ##
    listener.add_action("xAwsApiKey",
      action=elbv2.ListenerAction.forward(target_groups=[tg]),
      conditions=[elbv2.ListenerCondition.http_header("X-AWS-API-Key", [keys['key1']])],
      priority=1,
    )



    ##
    ## KMS Key used to encrypt secrets
    ## Alias: aws/secretsmanager
    ##


    ##
    ## Import an existing KMS Alias defined outside the CDK app, by the alias name.
    ##
    kms_key_alias = kms.Alias.from_alias_name(self, 'awsSecretsManagerKmsKeyAlias', 'alias/aws/secretsmanager')
    kms_key_arn   = kms_key_alias.key_arn

    ##
    ## Secrets with initial values
    ##
    secret = secretsmanager.CfnSecret(self, id="ApiKeys",
      description   = "ApiKeys",
      ##kms_key_id    = kms_key_id,
      name          = "alb-apikeys",
      secret_string = json.dumps(keys)
    )


    ##
    ## IAM Role used for Lambda function
    ##
    secret_lambda_role_arn = "arn:aws:iam::" + core.Aws.ACCOUNT_ID + ":role/alb-apikeys-rotator"
    secret_lambda_role     = iam.Role.from_role_arn(self, 
      id      ="ApiKeysRotatorIamRole", 
      role_arn=secret_lambda_role_arn,
      ## Whether the imported role can be modified by attaching policy resources to it.
      mutable =False)


    ##
    ## Lambda function to rotate the secret
    ##
    secret_lambda_function = lfn.Function(self, "ApiKeysRotator",
        code           = lfn.Code.asset("alb_apikeys_rotator"),
        function_name  = "alb_apikeys_rotator",
        handler        = "alb_apikeys_rotator.lambda_handler",
        timeout        = core.Duration.seconds(300),
        runtime        = lfn.Runtime.PYTHON_3_8,
        role           = secret_lambda_role,
        #environment    = {"ALBNAME":"sample"}
    )
    secret_lambda_function_arn = secret_lambda_function.function_arn

    ##
    ## When to rotate the secret
    ##
    secretsmanager.CfnRotationSchedule(self, id="ApiKeysRotationSchedule", 
      secret_id=secret.ref,
      rotation_lambda_arn=secret_lambda_function_arn, 
      rotation_rules=secretsmanager.CfnRotationSchedule.RotationRulesProperty(automatically_after_days=1))




