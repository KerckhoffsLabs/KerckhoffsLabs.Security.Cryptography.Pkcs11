using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 key wrap/unwrap integration tests, run against opencryptoki.</summary>
[Collection("OpenCryptoki")]
public sealed class WrapUnwrapKeyTests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    [ConditionalFact(nameof(Available))]
    public void AesKeyWrapPad_RoundTrip() => WrapUnwrapKeyTestCases.Assert_AesKeyWrapPad_RoundTrip(_backend);

    // The secure-defaults unwrap cases (Unwrap_AppliesSecureDefaults /
    // Unwrap_ExplicitExtractable_RequiresAllowInsecure) are not ported here: opencryptoki's C_UnwrapKey
    // rejects the minimal-usage unwrap template they use (CLASS/KEY_TYPE/TOKEN + injected
    // SENSITIVE/EXTRACTABLE) with CKR_ATTRIBUTE_READ_ONLY, where SoftHSM accepts it. Those cases verify
    // the library's secure-default *injection* (backend-independent logic), which stays covered on
    // SoftHSM and the managed mock (UnwrapSecureDefaultsTests.Pkcs11Mock). The real wrap/unwrap data
    // path on opencryptoki is exercised by AesKeyWrapPad_RoundTrip above.
}
