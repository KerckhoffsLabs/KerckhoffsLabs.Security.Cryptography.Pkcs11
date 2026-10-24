using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>HkdfPkcs11 over tpm2-pkcs11 — thin wrapper over <see cref="HkdfPkcs11TestCases"/>.</summary>
[Collection("Tpm2Pkcs11")]
public sealed class HkdfPkcs11Tests_Tpm2Pkcs11(Tpm2Pkcs11BackendFixture backend)
{
    private readonly Tpm2Pkcs11BackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void DeriveKey_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void DeriveKey_NullSalt_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_NullSalt_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Extract_MatchesBcl() => HkdfPkcs11TestCases.Assert_Extract_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void Expand_MatchesBcl() => HkdfPkcs11TestCases.Assert_Expand_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void DeriveKey_OnToken_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_DeriveKey_OnToken_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExtractKey_ThenExpandKey_MatchesBclViaSignProbe() => HkdfPkcs11TestCases.Assert_ExtractKey_ThenExpandKey_MatchesBclViaSignProbe(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ExtractKey_IsNotReadable() => HkdfPkcs11TestCases.Assert_ExtractKey_IsNotReadable(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void ByteResults_AreRefusedUnderTheDefaultPolicy() => HkdfPkcs11TestCases.Assert_ByteResults_AreRefusedUnderTheDefaultPolicy(_backend);

    [Fact(SkipUnless = nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available), SkipType = typeof(Tpm2Pkcs11BackendFixture), Skip = "Requires " + nameof(Tpm2Pkcs11BackendFixture.Tpm2Pkcs11Available))]
    public void DeriveKey_AtTheRfc5869Ceiling_MatchesBcl() => HkdfPkcs11TestCases.Assert_DeriveKey_AtTheRfc5869Ceiling_MatchesBcl(_backend);
}
