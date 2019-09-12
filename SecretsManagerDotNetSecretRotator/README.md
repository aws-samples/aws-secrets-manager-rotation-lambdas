# Secret Rotator

## A secret rotation plugin framework for AWS Secrets Manager
This frameworks aims to make the process of developing a custom secret rotation Lambda easier. It does this by providing a plugable interface that allows the developer to focus on just the logic required to create and change a secret. All the other logic to interface with AWS Secrets Manager is handled by the framework.

### Key Objects
| Name | Description |
| ----- | -----------|
| [SecretRotator](./Source/SecretRotator) Project | This project contains the framework that abstracts the AWS Secrets Manager. There is no implementation specific stuff located in here. |
| [SecretRotator<TSecret>](/Source/SecretRotator/SecretRotator.cs) Class | Imlement this abstract base class with your own implementation. The only requied method is CreateSecret. You can handle events for Set, Test, and Finish if there is additional logic you want to provide at those steps. |

## Let's Encrypt Example
An [example plugin](./Source/SecretRotator.LetsEncryptAccountKey/LetsEncryptAccountKeySecretRotator.cs) has been provided for [Let's Enrypt](https://letsencrypt.org/) account keys. Let's Encrypt is a free, automated, and open Certificate Authority. To issue SSL certificates you need an account key. This plugin creates the account key and stores it in AWS Secret Manager and changes the account key when a rotation event is triggered.

1. [Download this](https://raw.githubusercontent.com/paulfryer/secret-rotator/master/Source/SecretRotatorTemplate.json) cloud formation template.
2. Open install with AWS Cloud Formation via the AWS Console or Command Line.
3. After a few minutes you can view the secret value for your Let's Encrypt account. You will have a private and public PEM key.
4. A schedule is created to rotate the key every 7 days. You can change the rotation frequency or even rotate immediately from the AWS Secrets Manager console.

## Additional Resources
| Name | Description | Link |
| ----- | -----------| ----- |
| Lambda Rotation | Overview of how to implement Lambda based secret rotation directly. | https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets-lambda-function-overview.html |
