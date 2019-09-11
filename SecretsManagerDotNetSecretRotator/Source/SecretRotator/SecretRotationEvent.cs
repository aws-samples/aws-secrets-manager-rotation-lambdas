namespace SecretRotator
{
    public class SecretRotationEvent
    {
        public string ClientRequestToken { get; set; }
        public string SecretId { get; set; }
        public string Step { get; set; }
    }
}