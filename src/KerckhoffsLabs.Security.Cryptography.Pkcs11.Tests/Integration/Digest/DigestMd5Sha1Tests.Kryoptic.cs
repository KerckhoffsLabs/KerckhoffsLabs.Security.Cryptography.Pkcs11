using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

[Collection("Kryoptic")]
public sealed class DigestMd5Sha1Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Md5_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Md5_GatedByDefault(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Sha1_GatedByDefault() => DigestMd5Sha1TestCases.Assert_Sha1_GatedByDefault(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void Md5_AllowInsecureBypassesGate() => DigestMd5Sha1TestCases.Assert_Md5_AllowInsecureBypassesGate(_backend);
}
