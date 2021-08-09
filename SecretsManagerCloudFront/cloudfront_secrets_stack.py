

from aws_cdk import (
  aws_iam                as iam,
  aws_secretsmanager     as secretsmanager,
  aws_kms                as kms,
  aws_lambda             as lfn,
  aws_cloudfront         as cloudfront,
  aws_cloudfront_origins as cloudfront_origins,
  core,
)

import string
import random
import json


class CloudfrontSecretsStack(core.Stack):

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
    ## Sample CloudFront Distribution
    ##
    cfd = cloudfront.Distribution(self, 'sampleCloudFrontDistribution', 
      #default_behavior=cloudfront.BehaviorOptions(origin=cloudfront.OriginBase(
      default_behavior=cloudfront.BehaviorOptions(origin=cloudfront_origins.HttpOrigin(
        domain_name="target-backend-domain-name",
        custom_headers={"X-AWS-API-Key":keys['key1']})),
      comment="Sample CloudFront Distribution",
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
      name          = "cloudfront-apikeys",
      secret_string = json.dumps(keys)
    )


    ##
    ## IAM Role used for Lambda function
    ##
    secret_lambda_role_arn = "arn:aws:iam::" + core.Aws.ACCOUNT_ID + ":role/cloudfront-apikeys-rotator"
    secret_lambda_role     = iam.Role.from_role_arn(self, 
      id      ="ApiKeysRotatorIamRole", 
      role_arn=secret_lambda_role_arn,
      ## Whether the imported role can be modified by attaching policy resources to it.
      mutable =False)


    ##
    ## Lambda function to rotate the secret
    ##
    secret_lambda_function = lfn.Function(self, "ApiKeysRotator",
        code           = lfn.Code.asset("cloudfront_apikeys_rotator"),
        function_name  = "cloudfront_apikeys_rotator",
        handler        = "cloudfront_apikeys_rotator.lambda_handler",
        timeout        = core.Duration.seconds(300),
        runtime        = lfn.Runtime.PYTHON_3_8,
        role           = secret_lambda_role,
        environment    = {"DISTRIBUTION":cfd.distribution_id}
    )
    secret_lambda_function_arn = secret_lambda_function.function_arn

    ##
    ## When to rotate the secret
    ##
    secretsmanager.CfnRotationSchedule(self, id="ApiKeysRotationSchedule", 
      secret_id=secret.ref,
      rotation_lambda_arn=secret_lambda_function_arn, 
      rotation_rules=secretsmanager.CfnRotationSchedule.RotationRulesProperty(automatically_after_days=1))




