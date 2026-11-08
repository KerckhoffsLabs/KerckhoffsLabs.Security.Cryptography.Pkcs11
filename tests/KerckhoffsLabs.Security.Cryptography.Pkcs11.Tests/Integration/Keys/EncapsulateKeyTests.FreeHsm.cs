using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// C_EncapsulateKey/C_DecapsulateKey tests over FreeHSM with classical (RSA-OAEP, ECDH1)
/// mechanisms -- thin wrapper over <see cref="EncapsulateKeyTestCases"/>.
/// </summary>
[Collection("FreeHsm")]
public sealed class EncapsulateKeyTests_FreeHsm(FreeHsmBackendFixture backend)
{
    private readonly FreeHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void RsaOaep_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_RsaOaep_EncapsulateDecapsulate_RoundTrips(_backend);

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void Ecdh1_EncapsulateDecapsulate_RoundTrips() => EncapsulateKeyTestCases.Assert_Ecdh1_EncapsulateDecapsulate_RoundTrips(_backend);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(EncapsulateKeyTestCases.MontgomeryCurves), MemberType = typeof(EncapsulateKeyTestCases))]
    public void Ecdh1Montgomery_EncapsulateDecapsulate_ToNonExtractableAesKey(string curve) =>
        EncapsulateKeyTestCases.Assert_Ecdh1Montgomery_EncapsulateDecapsulate_ToNonExtractableAesKey(_backend, curve);

    [Theory(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    [MemberData(nameof(EncapsulateKeyTestCases.MlKemParameterSets), MemberType = typeof(EncapsulateKeyTestCases))]
    public void MlKem_EncapsulateDecapsulate_ToNonExtractableAesKey(CkpMlKem parameterSet) =>
        EncapsulateKeyTestCases.Assert_MlKem_EncapsulateDecapsulate_ToNonExtractableAesKey(_backend, parameterSet);

    // Before 2.6.1 FreeHSM reported a sensitive, unextractable shared key as CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE.
    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void EncapsulatedKeys_HaveNoProtectedHistory() => EncapsulateKeyTestCases.Assert_EncapsulatedKeys_HaveNoProtectedHistory(_backend);
}
