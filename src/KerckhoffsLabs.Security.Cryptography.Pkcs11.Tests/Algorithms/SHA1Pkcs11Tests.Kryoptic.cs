using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SHA1Pkcs11 over Kryoptic — thin wrapper over <see cref="SHA1Pkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class SHA1Pkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;
    public static bool KryopticAvailable => KryopticBackendFixture.KryopticAvailable;

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_GatedByDefault_Throws() => SHA1Pkcs11TestCases.Assert_ComputeHash_GatedByDefault_Throws(_backend);

    [ConditionalFact(nameof(KryopticAvailable))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl() => SHA1Pkcs11TestCases.Assert_ComputeHash_WithAllowInsecure_MatchesBcl(_backend);
}
