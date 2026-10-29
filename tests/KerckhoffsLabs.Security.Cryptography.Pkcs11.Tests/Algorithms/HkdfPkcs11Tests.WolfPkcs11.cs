using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HkdfPkcs11 over wolfPKCS11 — thin wrapper over <see cref="HkdfPkcs11TestCases"/>.</summary>
[Collection("WolfPkcs11")]
public sealed class HkdfPkcs11Tests_WolfPkcs11(WolfPkcs11BackendFixture backend)
{
    private readonly WolfPkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKey_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKey_NullSalt_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_NullSalt_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void Extract_MatchesBcl() => HkdfPkcs11TestCases.Assert_Extract_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void Expand_MatchesBcl() => HkdfPkcs11TestCases.Assert_Expand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void DeriveKey_OnToken_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_DeriveKey_OnToken_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ExtractKey_ThenExpandKey_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_ExtractKey_ThenExpandKey_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ExtractKey_IsNotReadable() => HkdfPkcs11TestCases.Assert_ExtractKey_IsNotReadable(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.WolfPkcs11Available), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "Requires " + nameof(WolfPkcs11BackendFixture.WolfPkcs11Available))]
    public void ByteResults_AreRefusedUnderTheDefaultPolicy() => HkdfPkcs11TestCases.Assert_ByteResults_AreRefusedUnderTheDefaultPolicy(_backend);

    [Fact(SkipUnless = nameof(WolfPkcs11BackendFixture.DerivedKeyReadbackAvailable), SkipType = typeof(WolfPkcs11BackendFixture), Skip = "wolfPKCS11 overrides a derived key's CKA_SENSITIVE and CKA_EXTRACTABLE from the base key")]
    public void DeriveKey_AtTheRfc5869Ceiling_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_AtTheRfc5869Ceiling_MatchesBcl(_backend);
}
