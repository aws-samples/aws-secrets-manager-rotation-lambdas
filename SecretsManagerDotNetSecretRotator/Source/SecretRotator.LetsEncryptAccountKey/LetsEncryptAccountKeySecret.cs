namespace SecretRotator.LetsEncryptAccountKey
{
    public class LetsEncryptAccountKeySecret : ISecret
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
        public string LetsEncryptKID { get; set; }
        public string LetsEncryptResult { get; set; }
    }
}
