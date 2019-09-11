using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.Lambda.Core;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Newtonsoft.Json;

namespace SecretRotator
{
    public abstract class SecretRotationFunction<TSecretRotator, TSecret>
        where TSecretRotator : ISecretRotator<TSecret>, new()
        where TSecret : ISecret
    {
        private readonly ISecretRotator<TSecret> secretRotator;
        private readonly IAmazonSecretsManager secretsManager;

        protected SecretRotationFunction()
        {
            secretRotator = new TSecretRotator();
            secretsManager = new AmazonSecretsManagerClient();
        }

        public async Task Handler(SecretRotationEvent @event, ILambdaContext context)
        {
            context.Logger.LogLine($"Processing step: {@event.Step}");
            context.Logger.LogLine(JsonConvert.SerializeObject(@event, Formatting.Indented));

            var pendingSecret = default(TSecret);

            if (@event.Step != Steps.CreateSecret)
            {
                context.Logger.LogLine($"Getting AWSPENDING secret: {@event.SecretId}");
                var getValueResult = await secretsManager.GetSecretValueAsync(new GetSecretValueRequest
                {
                    SecretId = @event.SecretId,
                    VersionStage = "AWSPENDING"
                });
                context.Logger.LogLine(
                    $"Got AWSPENDING secret, Name: {getValueResult.Name}, ARN: {getValueResult.ARN}, Version: {getValueResult.VersionId}, Stages: {string.Join(',', getValueResult.VersionStages)}");
                pendingSecret = JsonConvert.DeserializeObject<TSecret>(getValueResult.SecretString);
            }

            switch (@event.Step)
            {
                case Steps.CreateSecret:
                    context.Logger.LogLine($"Getting AWSCURRENT secret: {@event.SecretId}");
                    var getValueResult = await secretsManager.GetSecretValueAsync(new GetSecretValueRequest
                    {
                        SecretId = @event.SecretId,
                        VersionStage = "AWSCURRENT"
                    });
                    context.Logger.LogLine(
                        $"Got AWSCURRENT secret, Name: {getValueResult.Name}, ARN: {getValueResult.ARN}, Version: {getValueResult.VersionId}, Stages: {string.Join(',', getValueResult.VersionStages)}");

                    var currentSecret = JsonConvert.DeserializeObject<TSecret>(getValueResult.SecretString);
                    pendingSecret = await secretRotator.CreateSecret(currentSecret);
                    context.Logger.LogLine(
                        "Created new PENDING secret. About to store the secret with secret manager.");
                    var pubSecretResult = await secretsManager.PutSecretValueAsync(new PutSecretValueRequest
                    {
                        SecretId = @event.SecretId,
                        ClientRequestToken = @event.ClientRequestToken,
                        SecretString = JsonConvert.SerializeObject(pendingSecret),
                        VersionStages = new List<string> {"AWSPENDING"}
                    });
                    context.Logger.LogLine($"Secret storage result: {JsonConvert.SerializeObject(pubSecretResult)}");
                    break;
                case Steps.SetSecret:
                    await secretRotator.SetSecret(pendingSecret);
                    break;
                case Steps.TestSecret:
                    await secretRotator.TestSecret(pendingSecret);
                    break;
                case Steps.FinishSecret:
                    await secretRotator.FinishSecret(pendingSecret);
                    context.Logger.LogLine($"Calling describe secret method for secret: {@event.SecretId}");
                    var describeResult = await secretsManager.DescribeSecretAsync(new DescribeSecretRequest
                    {
                        SecretId = @event.SecretId
                    });
                    context.Logger.LogLine($"Describe result: {JsonConvert.SerializeObject(describeResult)}");
                    var currentVersionId = describeResult.VersionIdsToStages
                        .Single(i => i.Value.Contains("AWSCURRENT")).Key;
                    context.Logger.LogLine(
                        $"Found Current Version: {currentVersionId}. Now updating secret with new version: {@event.ClientRequestToken}");
                    var updateResult = await secretsManager.UpdateSecretVersionStageAsync(
                        new UpdateSecretVersionStageRequest
                        {
                            SecretId = @event.SecretId,
                            VersionStage = "AWSCURRENT",
                            RemoveFromVersionId = currentVersionId,
                            MoveToVersionId = @event.ClientRequestToken
                        });
                    context.Logger.LogLine($"Update secret result: {JsonConvert.SerializeObject(updateResult)}");
                    break;
                default:
                    throw new Exception($"Unsupported step type: {@event.Step}");
            }
        }

        private static class Steps
        {
            public const string CreateSecret = "createSecret";
            public const string SetSecret = "setSecret";
            public const string TestSecret = "testSecret";
            public const string FinishSecret = "finishSecret";
        }
    }
}