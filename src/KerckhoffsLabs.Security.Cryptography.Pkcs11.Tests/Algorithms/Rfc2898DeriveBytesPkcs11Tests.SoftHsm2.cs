using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// CKM_PKCS5_PBKD2 tests over SoftHsm -- thin wrapper over <see cref="Rfc2898DeriveBytesPkcs11TestCases"/>.
/// SoftHSM2 never registers this mechanism (CKM_PKCS5_PBKD2 appears only as a header constant, with
/// no dispatch anywhere in its crypto backend), so every case here skips via the shared assertions'
/// <c>RequireMechanism</c> check.
/// </summary>
[Collection("SoftHsm")]
public sealed class Rfc2898DeriveBytesPkcs11Tests_SoftHsm(SoftHsmBackendFixture backend)
{
    private readonly SoftHsmBackendFixture _backend = backend;
    public static bool Available => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(Available))]
    public void GetBytes_Sha1_MatchesRfc6070() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha1_MatchesRfc6070(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_Sha256_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha256_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_Sha384_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha384_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_Sha512_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_Sha512_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_LongerThanOneBlock_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_LongerThanOneBlock_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_EmptyPassword_MatchesBcl() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_EmptyPassword_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_DifferentPrf_ProducesDifferentOutput() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_DifferentPrf_ProducesDifferentOutput(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_SuccessiveCalls_ContinueOneStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_SuccessiveCalls_ContinueOneStream(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_AfterSettingSalt_RestartsStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_AfterSettingSalt_RestartsStream(_backend);

    [ConditionalFact(nameof(Available))]
    public void Reset_RestartsStream() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Reset_RestartsStream(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NullWorkspace_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullWorkspace_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NullPassword_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullPassword_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NullSalt_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NullSalt_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonPositiveIterations_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_NonPositiveIterations_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_UnsupportedHash_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_Ctor_UnsupportedHash_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_NonPositiveCount_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_NonPositiveCount_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void GetBytes_AfterDispose_Throws() => Rfc2898DeriveBytesPkcs11TestCases.Assert_GetBytes_AfterDispose_Throws(_backend);
}
