using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>SP800108HmacCounterKdfPkcs11Tests over OpenCryptoki — thin wrapper over <see cref="SP800108HmacCounterKdfPkcs11TestCases"/>.</summary>
[Collection("OpenCryptoki")]
public sealed class SP800108HmacCounterKdfPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void Ctor_NonGenericSecretKey_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_Ctor_NonGenericSecretKey_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void Ctor_UnsupportedPrfHash_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_Ctor_UnsupportedPrfHash_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void DeriveKey_NegativeLength_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_NegativeLength_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void DeriveKey_ZeroLength_IsNoOp() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_ZeroLength_IsNoOp(_backend);

    [ConditionalFact(nameof(Available))]
    public void DeriveKey_AfterDispose_Throws() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_AfterDispose_Throws(_backend);

    [ConditionalFact(nameof(Available))]
    public void DeriveKey_MatchesBcl() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void DeriveKey_DestinationSpan_MatchesBcl() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_DestinationSpan_MatchesBcl(_backend);

    [ConditionalFact(nameof(Available))]
    public void DeriveKey_OnToken_ReturnsNonExtractableKey() => SP800108HmacCounterKdfPkcs11TestCases.Assert_DeriveKey_OnToken_ReturnsNonExtractableKey(_backend);
}
