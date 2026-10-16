using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HkdfPkcs11 over Kryoptic — thin wrapper over <see cref="HkdfPkcs11TestCases"/>.</summary>
[Collection("Kryoptic")]
public sealed class HkdfPkcs11Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DeriveKey_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DeriveKey_NullSalt_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_NullSalt_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Extract_MatchesBcl() => HkdfPkcs11TestCases.Assert_Extract_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Expand_MatchesBcl() => HkdfPkcs11TestCases.Assert_Expand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void DeriveKey_OnToken_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_DeriveKey_OnToken_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ExtractKey_ThenExpandKey_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_ExtractKey_ThenExpandKey_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ExtractKey_IsNotReadable() => HkdfPkcs11TestCases.Assert_ExtractKey_IsNotReadable(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void ByteResults_AreRefusedUnderTheDefaultPolicy() => HkdfPkcs11TestCases.Assert_ByteResults_AreRefusedUnderTheDefaultPolicy(_backend);
}
