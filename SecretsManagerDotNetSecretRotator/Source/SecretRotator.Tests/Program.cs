using System;
using System.Threading.Tasks;
using Amazon.Lambda.Core;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using SecretRotator.LetsEncryptAccountKey;

namespace SecretRotator.Tests
{
    class Program
    {
        static void Main(string[] args)
        {
            Test().Wait();
        }

        static async Task Test()
        {
            var function = new LetsEncryptAccountKeySecretRotationFunction();

            var secretsManager = new AmazonSecretsManagerClient();


            var secretArn = string.Empty;

            secretArn = "arn:aws:secretsmanager:us-west-2:1234567890:secret:TestSecret-636999565209208171-icM7qC";

            if (string.IsNullOrEmpty(secretArn))
            {
                var createResult = await secretsManager.CreateSecretAsync(new CreateSecretRequest
                {
                    Name = $"TestSecret-{DateTime.UtcNow.Ticks}",
                    SecretString = "{}"
                });

                secretArn = createResult.ARN;
            }


            var @event = new SecretRotationEvent
            {
                ClientRequestToken = Guid.NewGuid().ToString(),
                SecretId = secretArn,
                Step = "createSecret"
            };

            var context = new TestContext();

            try
            {
                await function.Handler(@event, context);
                @event.Step = "setSecret";
                await function.Handler(@event, context);
                @event.Step = "testSecret";
                await function.Handler(@event, context);
                @event.Step = "finishSecret";
                await function.Handler(@event, context);
            }
            catch (Exception ex)
            {
                Console.Write(ex);
                throw;
            }
            finally
            {
                await secretsManager.DeleteSecretAsync(new DeleteSecretRequest
                {
                    SecretId = secretArn,
                    ForceDeleteWithoutRecovery = true
                });
            }
        }
    }

    public class TestContext : ILambdaContext
    {
        public string AwsRequestId { get; }
        public IClientContext ClientContext { get; }
        public string FunctionName { get; }
        public string FunctionVersion { get; }
        public ICognitoIdentity Identity { get; }
        public string InvokedFunctionArn { get; }
        public ILambdaLogger Logger => new ConsoleLogger();
        public string LogGroupName { get; }
        public string LogStreamName { get; }
        public int MemoryLimitInMB { get; }
        public TimeSpan RemainingTime { get; }
    }

    public class ConsoleLogger : ILambdaLogger
    {
        public void Log(string message)
        {
            Console.Write(message);
        }

        public void LogLine(string message)
        {
            Console.WriteLine(message);
        }
    }
}