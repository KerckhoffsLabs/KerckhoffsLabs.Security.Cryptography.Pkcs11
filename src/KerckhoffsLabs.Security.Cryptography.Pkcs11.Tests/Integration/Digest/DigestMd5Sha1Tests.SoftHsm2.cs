using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

[Collection("SoftHsm")]
public sealed class DigestMd5Sha1Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Md5_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Md5_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Sha1_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Sha1_GatedByDefault(_backend);

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Md5_AllowInsecureBypassesGate() => DigestMd5Sha1TestCases.Assert_Md5_AllowInsecureBypassesGate(_backend);
}
