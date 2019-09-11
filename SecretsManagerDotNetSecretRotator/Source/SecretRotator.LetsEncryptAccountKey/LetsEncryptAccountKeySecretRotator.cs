using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace SecretRotator.LetsEncryptAccountKey
{
    public class LetsEncryptAccountKeySecretRotator : SecretRotator<LetsEncryptAccountKeySecret>
    {
        public override async Task<LetsEncryptAccountKeySecret> CreateSecret(LetsEncryptAccountKeySecret currentSecret)
        {
            var pendingCsp = new RSACryptoServiceProvider(2048);

            var pendingSecret = new LetsEncryptAccountKeySecret
            {
                PublicKey = CryptoHelper.ExportPublicKey(pendingCsp),
                PrivateKey = CryptoHelper.ExportPrivateKey(pendingCsp)
            };

            if (string.IsNullOrEmpty(currentSecret.LetsEncryptKID))
            {
                var result = await CreateAccount(pendingCsp);
                pendingSecret.LetsEncryptKID = (string)result.account;
                pendingSecret.LetsEncryptResult = JsonConvert.SerializeObject(result.result);
            }
            else
            {
                var currentCsp = CryptoHelper.ImportPrivateKey(currentSecret.PrivateKey);

                var result = await AccountKeyRollover(currentCsp, pendingCsp, currentSecret.LetsEncryptKID);
                pendingSecret.LetsEncryptKID = currentSecret.LetsEncryptKID;
                pendingSecret.LetsEncryptResult = JsonConvert.SerializeObject(result.result);

            }


            return pendingSecret;
        }


        private static async Task<dynamic> AccountKeyRollover(RSACryptoServiceProvider currentCsp, RSACryptoServiceProvider pendingCsp, string kid)
        {
            using (var http = new HttpClient())
            {
                var directoryJson = await http.GetStringAsync("https://acme-v02.api.letsencrypt.org/directory");

                var directory = JsonConvert.DeserializeObject<dynamic>(directoryJson);
                string newNonceUrl = directory.newNonce;
                string keyChangeUrl = directory.keyChange;
                var newNonceResp = await http.GetAsync(newNonceUrl);
                var nonce = newNonceResp.Headers.GetValues("Replay-Nonce").SingleOrDefault();

                var currentParameters = currentCsp.ExportParameters(false);
                var pendingParameters = pendingCsp.ExportParameters(false);

                var innerProtectedJson = JsonConvert.SerializeObject(new
                {
                    alg = "RS256",
                    jwk = new
                    {
                        kty = "RSA",
                        e = EncodingHelper.UrlEncode(pendingParameters.Exponent),
                        n = EncodingHelper.UrlEncode(pendingParameters.Modulus)
                    },
                    url = keyChangeUrl
                }, Formatting.Indented);

                var innerPayloadJson = JsonConvert.SerializeObject(new
                {
                    account = kid,
                    oldKey = new
                    {
                        kty = "RSA",
                        e = EncodingHelper.UrlEncode(currentParameters.Exponent),
                        n = EncodingHelper.UrlEncode(currentParameters.Modulus)
                    }
                }, Formatting.Indented);


                var payload = EncodingHelper.UrlEncode(Encoding.UTF8.GetBytes(innerPayloadJson));
                var @protected = EncodingHelper.UrlEncode(Encoding.UTF8.GetBytes(innerProtectedJson));


                var dataToSign = $"{@protected}.{payload}";
                var signedData = pendingCsp.SignData(Encoding.UTF8.GetBytes(dataToSign), HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                var signature = EncodingHelper.UrlEncode(signedData);

                var innerJson = JsonConvert.SerializeObject(new
                {
                    payload,
                    @protected,
                    signature
                });



                var outterPayload = EncodingHelper.UrlEncode(Encoding.UTF8.GetBytes(innerJson));
                var outterProtected = EncodingHelper.UrlEncode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(new
                {
                    alg = "RS256",
                    kid,
                    nonce,
                    url = keyChangeUrl
                })));
                var outterDataToSign = $"{outterProtected}.{outterPayload}";
                var outterSignedData = currentCsp.SignData(Encoding.UTF8.GetBytes(outterDataToSign),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                var data = new
                {
                    @protected = outterProtected,
                    payload = outterPayload,
                    signature = EncodingHelper.UrlEncode(outterSignedData)
                };

                var json = JsonConvert.SerializeObject(data, Formatting.Indented);

                var content = new StringContent(json);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");
                var createAccountResp = await http.PostAsync(keyChangeUrl, content);
                var result = await createAccountResp.Content.ReadAsStringAsync();

                return new
                {
                    result
                };
            }
        }

        private static async Task<dynamic> CreateAccount(RSACryptoServiceProvider csp)
        {
            using (var http = new HttpClient())
            {
                var directoryJson = await http.GetStringAsync("https://acme-v02.api.letsencrypt.org/directory");

                var directory = JsonConvert.DeserializeObject<dynamic>(directoryJson);
                string newNonceUrl = directory.newNonce;
                string newAccountUrl = directory.newAccount;
                var newNonceResp = await http.GetAsync(newNonceUrl);
                var nonce = newNonceResp.Headers.GetValues("Replay-Nonce").SingleOrDefault();

                var parameters = csp.ExportParameters(false);

                var protectedJson = JsonConvert.SerializeObject(new
                {
                    alg = "RS256",
                    jwk = new
                    {
                        kty = "RSA",
                        e = EncodingHelper.UrlEncode(parameters.Exponent),
                        n = EncodingHelper.UrlEncode(parameters.Modulus)
                    },
                    url = newAccountUrl,
                    nonce
                }, Formatting.Indented);

                var payloadJson = JsonConvert.SerializeObject(new {termsOfServiceAgreed = true}, Formatting.Indented);


                var payload = EncodingHelper.UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
                var @protected = EncodingHelper.UrlEncode(Encoding.UTF8.GetBytes(protectedJson));


                var dataToSign = $"{@protected}.{payload}";
                var signedData = csp.SignData(Encoding.UTF8.GetBytes(dataToSign), HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                var signature = EncodingHelper.UrlEncode(signedData);

                var data = new
                {
                    payload,
                    @protected,
                    signature
                };

                var json = JsonConvert.SerializeObject(data, Formatting.Indented);

                var content = new StringContent(json);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");
                var createAccountResp = await http.PostAsync(newAccountUrl, content);
                var result = await createAccountResp.Content.ReadAsStringAsync();
                var account = createAccountResp.Headers.Location.AbsoluteUri;

                return new {account, result};
            }
        }
    }
}