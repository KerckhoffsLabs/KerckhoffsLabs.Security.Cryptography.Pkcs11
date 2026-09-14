using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SP800108HmacCounterKdfPkcs11Tests over NSS — thin wrapper over <see cref="SP800108HmacCounterKdfPkcs11TestCases"/>.</summary>
[Collection("Nss")]
public sealed class SP800108HmacCounterKdfPkcs11Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    // NSS refuses to derive a readable (extractable) key, so the read-back-and-compare cases skip.

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ctor_NonGenericSecretKey_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_Ctor_NonGenericSecretKey_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Ctor_UnsupportedPrfHash_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_Ctor_UnsupportedPrfHash_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DeriveKey_NegativeLength_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_NegativeLength_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DeriveKey_ZeroLength_IsNoOp() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_ZeroLength_IsNoOp(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DeriveKey_AfterDispose_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_AfterDispose_Throws(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void DeriveKey_MatchesBcl() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.ExtractableDeriveAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.ExtractableDeriveAvailable))]
    public void DeriveKey_DestinationSpan_MatchesBcl() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_DestinationSpan_MatchesBcl(_backend);

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void DeriveKey_OnToken_ReturnsNonExtractableKey() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_OnToken_ReturnsNonExtractableKey(_backend);
}
