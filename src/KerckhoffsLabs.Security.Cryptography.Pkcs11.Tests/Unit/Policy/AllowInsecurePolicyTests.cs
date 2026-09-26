using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

#pragma warning disable KLPKCS11009 // broken or deprecated mechanism
#pragma warning disable KLPKCS11010 // collision-broken hash for signatures
public sealed class AllowInsecurePolicyTests
{
    private static readonly ICryptoPolicy Policy = CryptoPolicy.AllowInsecure;

    public static TheoryData<PolicyRequest> EveryRequestKind() =>
    [
        new MechanismUseRequest(new Mechanism(CKM.CKM_DES_ECB), CryptoOperation.Encrypt),
        new HashUseRequest(HashAlgorithmName.MD5, CryptoOperation.Sign),
        new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, 512),
        new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256),
        new KeyTemplateRequest(CKO.CKO_SECRET_KEY, []),
        new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL),
        new KeyMaterialExportRequest(KeyMaterialExportKind.KemSharedSecret),
    ];

    [Theory]
    [MemberData(nameof(EveryRequestKind))]
    public void AllowsEveryRequestKind(PolicyRequest request)
        => Assert.True(Policy.Evaluate(request).IsAllowed);

    [Fact]
    public void Identity()
    {
        Assert.Equal("AllowInsecure", Policy.Name);
        Assert.True(Policy.AllowsOverride);
        Assert.Same(Policy, CryptoPolicy.AllowInsecure);
    }
}
#pragma warning restore KLPKCS11009
#pragma warning restore KLPKCS11010
