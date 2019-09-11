using System.Threading.Tasks;

namespace SecretRotator
{
    public interface ISecretRotator<TSecret> where TSecret : ISecret
    {
        Task<TSecret> CreateSecret(TSecret currentSecret);
        Task SetSecret(TSecret pendingSecret);
        Task TestSecret(TSecret pendingSecret);
        Task FinishSecret(TSecret pendingSecret);
    }
}