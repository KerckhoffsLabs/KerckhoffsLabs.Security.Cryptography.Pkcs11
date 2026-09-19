using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// CKM_PKCS5_PBKD2 tests over OpenCryptoki -- thin wrapper over <see cref="Rfc2898DeriveBytesPkcs11TestCases"/>.
/// The soft token's PBKDF2 (<c>compute_PKCS5_PBKDF2_HMAC</c>) is an internal helper used only to
/// derive its own master key from the SO/user PIN -- it is never registered as an application-facing
/// mechanism. Only the cases that actually invoke the mechanism skip via the shared assertions'
/// <c>RequireMechanism</c> check; the constructor/argument-validation cases (null checks,
/// <c>GetBytes(0)</c>, <c>ObjectDisposedException</c>, the zero-length short-circuit, etc.) never
/// touch the token and genuinely pass here.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class Rfc2898DeriveBytesPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_Sha1_MatchesRfc6070() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha1_MatchesRfc6070(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_Sha256_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha256_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_Sha384_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha384_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_Sha512_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha512_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_LongerThanOneBlock_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_LongerThanOneBlock_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_EmptyPassword_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_EmptyPassword_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_DifferentPrf_ProducesDifferentOutput() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_DifferentPrf_ProducesDifferentOutput(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_SuccessiveCalls_ContinueOneStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_SuccessiveCalls_ContinueOneStream(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_AfterSettingSalt_RestartsStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_AfterSettingSalt_RestartsStream(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Reset_RestartsStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Reset_RestartsStream(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ctor_NullWorkspace_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullWorkspace_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ctor_NullPassword_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullPassword_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ctor_NullSalt_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullSalt_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ctor_NonPositiveIterations_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NonPositiveIterations_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void Ctor_UnsupportedHash_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_NonPositiveCount_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_NonPositiveCount_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void GetBytes_AfterDispose_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_AfterDispose_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void HashAlgorithm_ReturnsConstructedValue() => Rfc2898DeriveBytesPkcs11TestCases.Assert_HashAlgorithm_ReturnsConstructedValue(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StaticPbkdf2_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StaticPbkdf2_DestinationSpan_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_DestinationSpan_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StaticPbkdf2_ZeroOutputLength_ReturnsEmptyWithNoTokenCall() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_ZeroOutputLength_ReturnsEmptyWithNoTokenCall(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StaticPbkdf2_NullWorkspace_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_NullWorkspace_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StaticPbkdf2_NegativeOutputLength_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_NegativeOutputLength_Throws(_backend);

    [Fact(SkipUnless = nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable), SkipType = typeof(OpenCryptokiBackendFixture), Skip = "Requires " + nameof(OpenCryptokiBackendFixture.OpenCryptokiAvailable))]
    public void StaticPbkdf2_UnsupportedHash_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_UnsupportedHash_Throws(_backend);
}
