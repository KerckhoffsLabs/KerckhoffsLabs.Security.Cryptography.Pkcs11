using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HkdfPkcs11 over NSS — thin wrapper over <see cref="HkdfPkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class HkdfPkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS refuses to derive a readable (extractable) key, so the read-back cases wait on
    // ExtractableDeriveAvailable; the sign-probe cases prove the on-token overloads today.

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void DeriveKey_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void DeriveKey_NullSalt_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_NullSalt_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void Extract_MatchesBcl() => HkdfPkcs11TestCases.Assert_Extract_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void Expand_MatchesBcl() => HkdfPkcs11TestCases.Assert_Expand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DeriveKey_OnToken_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_DeriveKey_OnToken_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExtractKey_ThenExpandKey_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_ExtractKey_ThenExpandKey_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ExtractKey_IsNotReadable() => HkdfPkcs11TestCases.Assert_ExtractKey_IsNotReadable(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void ByteResults_AreRefusedUnderTheDefaultPolicy() => HkdfPkcs11TestCases.Assert_ByteResults_AreRefusedUnderTheDefaultPolicy(_backend);
}
