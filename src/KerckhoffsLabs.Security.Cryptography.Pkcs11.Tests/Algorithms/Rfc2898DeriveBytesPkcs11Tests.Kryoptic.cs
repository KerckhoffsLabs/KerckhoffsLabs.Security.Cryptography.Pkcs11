using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// CKM_PKCS5_PBKD2 tests over Kryoptic -- thin wrapper over <see cref="Rfc2898DeriveBytesPkcs11TestCases"/>.
/// Gated only on backend availability: the mechanism-support check (<c>RequireMechanism</c>) lives
/// inside the shared assertions, matching how other backend-specific mechanism gaps are handled
/// elsewhere.
/// </summary>
[Collection("Kryoptic")]
public sealed class Rfc2898DeriveBytesPkcs11Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_Sha1_MatchesRfc6070() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha1_MatchesRfc6070(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_Sha256_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha256_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_Sha384_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha384_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_Sha512_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha512_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_LongerThanOneBlock_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_LongerThanOneBlock_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_EmptyPassword_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_EmptyPassword_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_DifferentPrf_ProducesDifferentOutput() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_DifferentPrf_ProducesDifferentOutput(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_SuccessiveCalls_ContinueOneStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_SuccessiveCalls_ContinueOneStream(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_AfterSettingSalt_RestartsStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_AfterSettingSalt_RestartsStream(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Reset_RestartsStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Reset_RestartsStream(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ctor_NullWorkspace_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullWorkspace_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ctor_NullPassword_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullPassword_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ctor_NullSalt_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullSalt_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ctor_NonPositiveIterations_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NonPositiveIterations_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void Ctor_UnsupportedHash_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_NonPositiveCount_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_NonPositiveCount_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void GetBytes_AfterDispose_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_AfterDispose_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void HashAlgorithm_ReturnsConstructedValue() => Rfc2898DeriveBytesPkcs11TestCases.Assert_HashAlgorithm_ReturnsConstructedValue(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void StaticPbkdf2_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void StaticPbkdf2_DestinationSpan_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_DestinationSpan_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void StaticPbkdf2_ZeroOutputLength_ReturnsEmptyWithNoTokenCall() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_ZeroOutputLength_ReturnsEmptyWithNoTokenCall(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void StaticPbkdf2_NullWorkspace_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_NullWorkspace_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void StaticPbkdf2_NegativeOutputLength_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_NegativeOutputLength_Throws(_backend);

    [Fact(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    public void StaticPbkdf2_UnsupportedHash_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_StaticPbkdf2_UnsupportedHash_Throws(_backend);
}
