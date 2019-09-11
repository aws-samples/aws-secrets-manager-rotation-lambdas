
using Amazon.Lambda.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]


namespace SecretRotator.LetsEncryptAccountKey
{
    public class LetsEncryptAccountKeySecretRotationFunction : SecretRotationFunction<LetsEncryptAccountKeySecretRotator, LetsEncryptAccountKeySecret>
    {
    }
}