using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Policy;

#pragma warning disable KLPKCS11009 // broken or deprecated mechanism
#pragma warning disable KLPKCS11010 // collision-broken hash for signatures
public sealed class AllowInsecurePolicyTests
{
    private static readonly ICryptoPolicy Policy = CryptoPolicy.AllowInsecure;

    // Keyed by request-kind name so each theory row is serializable and shows up individually in
    // test explorers; the requests themselves are built on demand.
    private static readonly Dictionary<string, Func<PolicyRequest>> RequestsByKind = new()
    {
        [nameof(MechanismUseRequest)] = () => new MechanismUseRequest(new Mechanism(CKM.CKM_DES_ECB), CryptoOperation.Encrypt),
        [nameof(HashUseRequest)] = () => new HashUseRequest(HashAlgorithmName.MD5, CryptoOperation.Sign),
        [nameof(RsaKeyGenerationRequest)] = () => new RsaKeyGenerationRequest(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN, 512),
        [nameof(EcKeyGenerationRequest)] = () => new EcKeyGenerationRequest(Pkcs11ECCurve.NamedCurves.NistP256),
        [nameof(KeyTemplateRequest)] = () => new KeyTemplateRequest(CKO.CKO_SECRET_KEY, []),
        [nameof(KeyAgreementKdfRequest)] = () => new KeyAgreementKdfRequest(CKM.CKM_ECDH1_DERIVE, CKD.CKD_NULL),
        [nameof(KeyMaterialExportRequest)] = () => new KeyMaterialExportRequest(KeyMaterialExportKind.KemSharedSecret),
    };

    public static TheoryData<string> EveryRequestKind() => [.. RequestsByKind.Keys];

    [Theory]
    [MemberData(nameof(EveryRequestKind))]
    public void AllowsEveryRequestKind(string requestKind)
        => Assert.True(Policy.Evaluate(RequestsByKind[requestKind]()).IsAllowed);

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
