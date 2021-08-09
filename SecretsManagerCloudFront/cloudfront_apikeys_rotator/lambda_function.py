#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError
import json
import logging
import string
import random
import os
import re

## https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-lambda-function-overview.html#rotation-explanation-of-steps
## Step can be:
##  - createSecret: the Lambda function generates a new version of the secret. 
##                  Secrets Manager then labels the new version of the secret 
##                  with the staging label AWSPENDING to mark it as the 
##                  in-process version of the secret.
##  - setSecret...: rotation function retrieves the version of the secret 
##                  labeled AWSPENDING from Secrets Manager
##  - testSecret..: the Lambda function verifies the AWSPENDING version of the secret
##  - finishSecret: move the label AWSCURRENT from the current version 
##                  to this new version of the secret so your clients start using it.

##
## There are three steps to care about: create, set, and finish
##   - createSecret: writes the new AWSPENDING secret
##   - setSecret...: will update CloudFront
##   - finishSecret: changes AWSPENDING to AWSCURRENT 
##


##
## ℹ️ By default, the LOG LEVEL will be INFO.
## ⚠️ Setting the LOG LEVEL to DEBUG will print secrets to the CloudWatch Logs.
## 🛑 DO NOT SET LOG LEVEL TO DEBUG UNLESS YOU KNOW WHAT YOU ARE DOING.
##
logger   = logging.getLogger()
loglevel = os.environ.get('LOGLEVEL', 'INFO')
if (loglevel.lower() == "debug"):
  logger.setLevel(logging.DEBUG)
else:
  logger.setLevel(logging.INFO)


secretsmanager = boto3.client('secretsmanager')
cloudfront     = boto3.client('cloudfront')


######################################################
##
## Get Secret utility function
## - This function is used to get the current secret value
##
######################################################

def get_secret(secret_id, stage="AWSCURRENT", token=None):
  ##
  ## https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html#SecretsManager.Client.get_secret_value
  ##
  logger.debug("Getting [%s] Secret: [%s]" % (stage, secret_id))
  response=secretsmanager.get_secret_value(SecretId=secret_id,
                                          VersionStage=stage)
  secret_value = response['SecretString']
  logger.debug("Retrieved Secret: [%s]", secret_value)
  return secret_value

######################################################
##
## Generate API Key
## - Generates a random-string API key.
##
######################################################
def key_generator(size=16):
  chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
  key   = ''.join(random.choice(chars) for _ in range(size))
  return key



######################################################
##
## Update Custom API Key Header in CloudFront
## - Gets a list of CloudFront Distributions
## - Gets the *ALIASES* environment variable
## - ALIASES is a list of domain names seperated by a comma.
## - If a CloudFront Distribution contains an *alias*
##   in the *ALIASES* environment variable, then
##   set the API Key header.
##
######################################################
def set_api_key_in_cloudfront(secret_value=None):
  if (secret_value == None):
    return 1

  logger.debug("Setting API Key in Cloudfront: %s" % secret_value)
  ##
  ## Get CloudFront Distributions
  ## Set AWS API Key
  ##
  response = cloudfront.list_distributions()
  if "DistributionList" in response:
    for itm in response['DistributionList']["Items"]:
        ##
        ## ID is needed to pull the DistributionConfig
        ##
        distribution_id = itm['Id'] # EXXXXXXXXXXXX
        etag            = ""
        ##
        ## Domain Name is the CloudFront generated (random) domain name.
        ##
        domain_name = itm['DomainName'] # dxxxxxxxxxxxxx.cloudfront.net
        ##
        ## Aliases are the CNAME's, or ALT names, that the CloudFront distribution responds too.
        ## Assume that the Aliases match our two targets: frontend or backend.
        ##
        aliases     = itm['Aliases']['Items']

        ##
        ## Get Environment Variables
        ##
        aliases_env               = os.environ.get("ALIASES",      None)
        distribution_id_to_rotate = os.environ.get("DISTRIBUTION", None)
        rotate_this_distribution  = False

        ##
        ## If Distribution ID matches the DISTRIBUTION env var, rotate.
        ##
        if (distribution_id_to_rotate == distribution_id):
          rotate_this_distribution = True

        ##
        ## Loop through the list of aliases.
        ## If one of the aliases matches the ALIASES env var, rotate.
        ##
        if (aliases_env != None):
          aliases_to_rotate = aliases_env.split(",")
          for alias in aliases:
            if alias in aliases_to_rotate:
              rotate_this_distribution = True

        ##
        ## If Distribution ID or Aliases matched, update headers
        ##
        if rotate_this_distribution:
          ##
          ## Download the current config
          ##
          distribution   = cloudfront.get_distribution_config(Id=distribution_id)
          etag           = distribution['ETag']
          ##
          ## Custom Headers contain the API KEY sent to the Origin from Cloudfront.
          ## Download the current Headers
          ##
          custom_headers = None
          if 'DistributionConfig' in distribution:
            if 'Origins' in distribution['DistributionConfig']:
              if 'Items' in distribution['DistributionConfig']['Origins']:
                if len(distribution['DistributionConfig']['Origins']['Items']):
                  if 'CustomHeaders' in distribution['DistributionConfig']['Origins']['Items'][0]:
                    custom_headers = distribution['DistributionConfig']['Origins']['Items'][0]['CustomHeaders']
                  else:
                    distribution['DistributionConfig']['Origins']['Items'][0]['CustomHeaders'] = {'Items'=[]}

          ##
          ## Roll through all headers to find the 'X-AWS-API-Key'
          ##
          i = 0
          custom_headers_new = []
          if (custom_headers == None):
            logger.info("Custom Headers not found, adding fresh")
            custom_headers_new.append({"HeaderName":'X-AWS-API-Key', "HeaderValue":secret_value})
          else:
            for ch in custom_headers["Items"]:
              logger.debug(ch)
              ##'Items': [{
              ##  'HeaderName':  'X-AWS-API-Key',
              ##  'HeaderValue': 'xxxxxxxxxxxxxxxx'
              ## }]
              if (custom_headers["Items"][i]["HeaderName"] == 'X-AWS-API-Key'):
                logger.debug("current header: %s" % custom_headers["Items"][i])
                logger.debug("new header: %s" % {"HeaderName":'X-AWS-API-Key', "HeaderValue":secret_value})
                ##
                ## Set 'X-AWS-API-Key' to the value of the new secret
                ##
                custom_headers_new.append({"HeaderName":'X-AWS-API-Key', "HeaderValue":secret_value})
              else:
                custom_headers_new.append(custom_headers["Items"][i])
              i = i + 1
          ##
          ## Update custom headers
          ##
          distribution['DistributionConfig']['Origins']['Items'][0]['CustomHeaders']['Items'] = custom_headers_new

          ##
          ## Update Cloudfront distribution with new settings.
          ##
          cloudfront.update_distribution(DistributionConfig=distribution['DistributionConfig'],\
                                         Id=distribution_id,\
                                         IfMatch=etag)

  return 0

######################################################
##
## step-specific functions
##
######################################################

##
## - The Lambda function generates a new version of the secret. 
## - Secrets Manager then labels the new version of the secret 
##   with the staging label AWSPENDING to mark it as the 
##   in-process version of the secret.
## - This method first checks for the existence of a secret for the passed in token. 
## - If one does not exist, it will generate a
##   new secret and put it with the passed in token.
##
def create_secret(secret_id, token=None):
  logger.debug("CREATING SECRET")

  old_secret_value      = get_secret(secret_id, stage="AWSCURRENT", token=token)
  logger.debug("* old_secret_value 1: %s" % str(type(old_secret_value)))
  logger.debug("* old_secret_value 1: %s" % str(old_secret_value))
  old_secret_value_json = json.loads(old_secret_value)
  logger.debug("* old_secret_value_json 1: %s" % str(type(old_secret_value_json)))
  logger.debug("* old secret: %s" % old_secret_value)

  # Now try to get the secret version, if that fails, put a new secret
  try:
    pending_secret_value = secretsmanager.get_secret_value(SecretId=secret_id, VersionId=token, VersionStage="AWSPENDING")
    logger.info("createSecret: Successfully retrieved secret for %s." % secret_id)
    logger.debug("* pending secret: %s" % pending_secret_value)

  except secretsmanager.exceptions.ResourceNotFoundException:

    logger.debug("* old_secret_value..... 2: %s" % str(type(old_secret_value)))
    logger.debug("* old_secret_value_json 2: %s" % str(type(old_secret_value_json)))
    logger.debug("* old_secret_value_json 2: %s" % str(old_secret_value_json))
    
    old_secret_value_json=json.loads(old_secret_value)
    logger.debug("* old_secret_value..... 3: %s" % str(type(old_secret_value)))
    logger.debug("* old_secret_value_json 3: %s" % str(type(old_secret_value_json)))
    logger.debug("* old_secret_value_json 3: %s" % str(old_secret_value_json))

    new_secret_value = {
      "key1": old_secret_value_json["key2"],
      "key2": old_secret_value_json["key3"],
      "key3": key_generator(),
    }
    logger.debug("* new secret: %s" % json.dumps(new_secret_value).replace("\\", ""))

    ##
    ## https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/secretsmanager.html#SecretsManager.Client.put_secret_value
    ##
    secretsmanager.put_secret_value(SecretId=secret_id, ClientRequestToken=token, SecretString=json.dumps(new_secret_value).replace("\\", ""), VersionStages=['AWSPENDING'])
    logger.info("createSecret: Successfully put secret for secret_id %s and version %s." % (secret_id, token))

  return 0

##
## - Rotation function retrieves the version of the secret 
##   labeled AWSPENDING from Secrets Manager
## - This method should set the AWSPENDING secret in the service that 
##   the secret belongs to.
## - This method will take the value of the AWSPENDING secret and set the 
##   API Key in CloudFront
##
def set_secret(secret_id, token=None):
  logger.debug("SETTING SECRET")
  secret_value = get_secret(secret_id, stage="AWSPENDING",token=token)
  logger.debug("* secret_value.....: %s" % secret_value)
  logger.debug("* secret_value.....: %s" % str(type(secret_value)))
  secret_value_json = json.loads(secret_value.replace("'", '"').replace("\\", ""))
  logger.debug("* secret_value_json: %s" % str(repr(secret_value_json)))
  logger.debug("* secret_value_json: %s" % str(type(secret_value_json)))
  logger.debug("setting api key in cloudfront: %s" % secret_value_json["key3"])
  set_api_key_in_cloudfront(secret_value_json["key3"])
  return 0

##
## - The Lambda function verifies the AWSPENDING version of the secret
## - This method should validate that the AWSPENDING secret works in 
##   the service that the secret belongs to.
##
def test_secret(secret_id, token=None):
  logger.debug("TESTING SECRET")
  secret_value_current = get_secret(secret_id, stage="AWSCURRENT",token=token)
  secret_value_pending = get_secret(secret_id, stage="AWSPENDING",token=token)
  logger.debug("* current secret: %s" % secret_value_current)
  logger.debug("* pending secret: %s" % secret_value_pending)
  return 0

##
## - Move the label AWSCURRENT from the current version 
##   to this new version of the secret so your clients start using it.
## - This method finalizes the rotation process by marking the secret 
##   version passed in as the AWSCURRENT secret.
##
def finish_secret(secret_id, token=None):
  logger.debug("FINISHING SECRET")
  secret_value = get_secret(secret_id, stage="AWSPENDING",token=token)
  logger.debug("* pending secret: %s" % secret_value)

  # Describe the secret to get the current version
  metadata = secretsmanager.describe_secret(SecretId=secret_id)
  current_version = None
  for version in metadata["VersionIdsToStages"]:
      if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
          if version == token:
              # The correct version is already marked as current, return
              logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, secret_id))
              return
          current_version = version
          break

  # Finalize by staging the secret version current
  secretsmanager.update_secret_version_stage(SecretId=secret_id, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)

  return 0


######################################################
##
## Main function of the Lambda
##
######################################################

def lambda_handler(event, context):
    logger.debug(event)
    
    step      = event["Step"]
    secret_id = event["SecretId"]
    token     = ""
    if 'ClientRequestToken' in event:
      token = event['ClientRequestToken']

    ##
    ## Ensure the version is staged correctly
    ##
    metadata = secretsmanager.describe_secret(SecretId=secret_id)
    if not metadata['RotationEnabled']:
      logger.error("Secret %s is not enabled for rotation" % secret_id)
      raise ValueError("Secret %s is not enabled for rotation" % secret_id)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
      logger.error("Secret version %s has no stage for rotation of secret %s." % (token, secret_id))
      raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, secret_id))
    if "AWSCURRENT" in versions[token]:
      logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, secret_id))
      return
    elif "AWSPENDING" not in versions[token]:
      logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, secret_id))
      raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, secret_id))




    logger.debug("Step.....: [%s] (%s)" % (step, step.lower()))
    logger.debug("Secret ID: [%s]" % secret_id)
    logger.debug("Token....: [%s]" % token)
    ##
    ## Steps are lowercase+Secret:
    ##   - createSecret
    ##   - setSecret
    ##   - testSecret
    ##   - finishSecret
    ##
    if (step.lower() == "createsecret"):
      logger.debug("CreateSecret step")
      create_secret(secret_id, token)
    elif (step.lower() == "setsecret"):
      logger.debug("SetSecret step")
      set_secret(secret_id, token)
    elif (step.lower() == "testsecret"):
      logger.debug("TestSecret step")
      test_secret(secret_id, token)
    elif (step.lower() == "finishsecret"):
      logger.debug("FinishSecret step")
      finish_secret(secret_id, token)
    else:
      logger.debug("unknown step: %s" % step)

    return {
        'statusCode': 200,
        'body': "done."
    }






