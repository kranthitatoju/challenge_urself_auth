using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace challenge_urself_auth_api.Services;

public class RsaKeyService
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly string _keyId = Guid.NewGuid().ToString("N")[..8];

    public SigningCredentials SigningCredentials =>
        new(new RsaSecurityKey(_rsa) { KeyId = _keyId }, SecurityAlgorithms.RsaSha256);

    public RsaSecurityKey PublicKey
    {
        get
        {
            var pub = RSA.Create();
            pub.ImportParameters(_rsa.ExportParameters(false));
            return new RsaSecurityKey(pub) { KeyId = _keyId };
        }
    }

    public object Jwks()
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(PublicKey);
        return new { keys = new[] { jwk } };
    }
}
