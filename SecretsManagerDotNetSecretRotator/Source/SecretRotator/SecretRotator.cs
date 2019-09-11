using System.Threading.Tasks;

namespace SecretRotator
{
    public abstract class SecretRotator<TSecret> : ISecretRotator<TSecret> where TSecret : ISecret
    {
        public delegate Task SecretHandler(TSecret secret);


        public abstract Task<TSecret> CreateSecret(TSecret currentSecret);

        public Task SetSecret(TSecret pendingSecret)
        {
            return Set != null ? Set(pendingSecret) : Task.FromResult(0);
        }

        public Task TestSecret(TSecret pendingSecret)
        {
            return Test != null ? Test(pendingSecret) : Task.FromResult(0);
        }

        public Task FinishSecret(TSecret pendingSecret)
        {
            return Finish != null ? Finish(pendingSecret) : Task.FromResult(0);
        }

        public event SecretHandler Set;
        public event SecretHandler Test;
        public event SecretHandler Finish;
    }
}