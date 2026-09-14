using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>MD5Pkcs11 over Kryoptic — thin wrapper over <see cref="MD5Pkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class MD5Pkcs11Tests_Kryoptic(KryopticBackendFixture f)
{
    private readonly KryopticBackendFixture _backend = f;

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ComputeHash_GatedByDefault_Throws() => MD5Pkcs11TestCases.Assert_ComputeHash_GatedByDefault_Throws(_backend);

    [ConditionalFact(typeof(KryopticBackendFixture), nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ComputeHash_WithAllowInsecure_MatchesBcl() => MD5Pkcs11TestCases.Assert_ComputeHash_WithAllowInsecure_MatchesBcl(_backend);
}
