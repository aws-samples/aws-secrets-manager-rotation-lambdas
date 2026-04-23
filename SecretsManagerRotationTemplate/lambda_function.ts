import * as AWS from "aws-sdk";

/**
 * This is a template for creating an AWS Secrets Manager rotation lambda
 * Mostly a translation of https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerRotationTemplate/lambda_function.py
 *
 * @summary Secrets Manager Rotation Template
 * @param {string} event Lambda dictionary of event parameters. These keys must include the following:
 *          - SecretId: The secret ARN or identifier
 *          - ClientRequestToken: The ClientRequestToken of the secret version
 *          - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)
 * @param {LambdaContext} context The Lambda runtime information
 *
 * @throws {ValueError} If the secret is not properly configured for rotation
 * @throws {AWS.AWSError} If the secret with the specified arn and stage does not exist
 */
exports.handler = async (event: any, context: any, callback: any) => {
  const parsedEvent = JSON.parse(event);
  const arn = parsedEvent.SecretId;
  const token = parsedEvent.ClientRequestToken;
  const step = parsedEvent.Step;

  // Setup the client
  const secretsClient = new AWS.SecretsManager();

  // Make sure the version is staged correctly
  const metadata = await secretsClient
    .describeSecret({
      SecretId: arn,
    })
    .promise();

  if (!metadata["RotationEnabled"]) {
    console.log(`Secret ${arn} is not enabled for rotation`);
    const error = new ValueError(`Secret ${arn} is not enabled for rotation`);
  }

  const versions = metadata.VersionIdsToStages;
  if (!versions[token]) {
    console.log(
      `Secret version ${token} has no stage for rotation of secret ${arn}.`
    );
    throw new ValueError(
      `Secret version ${token} has no stage for rotation of secret ${arn}.`
    );
  }

  if (versions[token].find((v) => v === "AWSCURRENT")) {
    console.log(
      `Secret version ${token} already set as AWSCURRENT for secret ${arn}.`
    );
    return;
  } else if (!versions[token].find((v) => v === "AWSPENDING")) {
    console.log(
      `Secret version ${token} not set as AWSPENDING for rotation of secret ${arn}.`
    );
    throw new ValueError(
      `Secret version ${token} not set as AWSPENDING for rotation of secret ${arn}.`
    );
  }

  switch (step) {
    case "createSecret":
      await createSecret(secretsClient, arn, token);
      return;
    case "setSecret":
      await setSecret(secretsClient, arn, token);
      return;
    case "testSecret":
      await testSecret(secretsClient, arn, token);
      return;
    case "finishSecret":
      await finishSecret(secretsClient, arn, token);
      return;
  }

  throw new ValueError("Invalid step parameter");
};

/**
 * This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
 * new secret and put it with the passed in token.
 *
 * @summary Create the secret
 * @param {AWS.SecretsManager} secretsClient The secrets manager service client
 * @param {string} arn The secret ARN or other identifier
 * @param {string} token The ClientRequestToken associated with the secret version
 * @throws {AWS.AWSError} If the secret with the specified arn and stage does not exist
 */
async function createSecret(
  secretsClient: AWS.SecretsManager,
  arn: string,
  token: string
) {
  // Make sure the current secret exists
  await secretsClient
    .getSecretValue({
      SecretId: arn,
      VersionStage: "AWSCURRENT",
    })
    .promise();

  // Now try to get the secret version, if that fails, put a new secret
  try {
    await secretsClient.getSecretValue({
      SecretId: arn,
      VersionId: token,
      VersionStage: "AWSPENDING",
    });
    console.log(`createSecret: Successfully retrieved secret for ${arn}.`);
  } catch (e) {
    // Get exclude characters from environment variable
    const ExcludeCharacters = process.env.EXCLUDE_CHARACTERS || "/@\"'\\";
    // Generate a random password
    const password = await secretsClient
      .getRandomPassword({
        ExcludeCharacters,
      })
      .promise();

    // Put the secret
    secretsClient
      .putSecretValue({
        SecretId: arn,
        ClientRequestToken: token,
        SecretString: password.RandomPassword,
        VersionStages: ["AWSPENDING"],
      })
      .promise();
    console.log(
      `createSecret: Successfully put secret for ARN ${arn} and version ${token}.`
    );
  }
}

/**
 * This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
 * credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.
 *
 * @summary Set the secret
 * @param {AWS.SecretsManager} secretsClient - The secrets manager service client
 * @param {string} arn - The secret ARN or other identifier
 * @param {string} token - The ClientRequestToken associated with the secret version
 */
function setSecret(
  secretsClient: AWS.SecretsManager,
  arn: string,
  token: string
) {
  // This is where the secret should be set in the service
  throw new NotImplementedError();
}

/**
 * This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
 * is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
 * all of the expected permissions against the database.
 *
 * @summary Test the secret
 * @param {AWS.SecretsManager} secretsClient - The secrets manager service client
 * @param {string} arn - The secret ARN or other identifier
 * @param {string} token - The ClientRequestToken associated with the secret version
 */
function testSecret(
  secretsClient: AWS.SecretsManager,
  arn: string,
  token: string
) {
  // This is where the secret should be tested against the service
  throw new NotImplementedError();
}

/**
 * This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.
 *
 * @summary Finish the secret
 * @param {AWS.SecretsManager} secretsClient - The secrets manager service client
 * @param {string} arn - The secret ARN or other identifier
 * @param {string} token - The ClientRequestToken associated with the secret version
 * @throws {AWS.AWSError} If the secret with the specified arn does not exist
 */
async function finishSecret(
  secretsClient: AWS.SecretsManager,
  arn: string,
  token: string
) {
  // First describe the secret to get the current version
  const metadata = await secretsClient
    .describeSecret({
      SecretId: arn,
    })
    .promise();
  let currentVersion;
  for (let version of Object.keys(metadata.VersionIdsToStages)) {
    if (metadata.VersionIdsToStages[version].find(v => v === "AWSCURRENT")) {
      if (version == token) {
        // The correct version is already marked as current, return
        console.info(
          `finishSecret: Version ${version} already marked as AWSCURRENT for ${arn}`
        );
        return;
      }
      currentVersion = version;
      break;
    }
  }

  // Finalize by staging the secret version current
  await secretsClient.updateSecretVersionStage({
    SecretId: arn,
    VersionStage: "AWSCURRENT",
    MoveToVersionId: token,
    RemoveFromVersionId: currentVersion
  }).promise();
  console.info(
    `finishSecret: Successfully set AWSCURRENT stage to version ${token} for secret ${arn}.`
  );
}

//#region Custom error impls to match original python code
class ValueError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "ValueError";
  }
}

class NotImplementedError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "NotImplementedError";
  }
}
//#endregion
