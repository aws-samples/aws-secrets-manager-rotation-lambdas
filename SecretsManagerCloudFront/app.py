from aws_cdk import core

from cloudfront_secrets_stack import CloudfrontSecretsStack

app = core.App()
env = {'region': 'us-east-1'}

CloudfrontSecretsStack(app, "CloudfrontSecretsStack", env=env, description="CloudFront Secrets")

app.synth()

