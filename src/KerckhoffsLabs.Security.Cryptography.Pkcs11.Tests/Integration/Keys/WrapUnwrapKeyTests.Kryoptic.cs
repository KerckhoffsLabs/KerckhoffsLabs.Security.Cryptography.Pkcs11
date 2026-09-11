using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 key wrap/unwrap integration tests, run against Kryoptic.
/// The shared <see cref="WrapUnwrapKeyTestCases"/> assertions use <see cref="CKM.CKM_AES_KEY_WRAP_PAD"/>
/// unconditionally (no internal skip); Kryoptic 1.5.2 implements the modern NIST SP800-38F
/// <see cref="CKM.CKM_AES_KEY_WRAP_KWP"/> but not the legacy PAD variant, so this wrapper gates on it.</summary>
[Collection("Kryoptic")]
public sealed class WrapUnwrapKeyTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;
    public static bool Available => KryopticBackendFixture.KryopticAvailable;

    private void RequireAesKeyWrapPad() => _backend.RequireMechanism(CKM.CKM_AES_KEY_WRAP_PAD);

    [ConditionalFact(nameof(Available))]
    public void AesKeyWrapPad_RoundTrip()
    {
        RequireAesKeyWrapPad();
        WrapUnwrapKeyTestCases.Assert_AesKeyWrapPad_RoundTrip(_backend);
    }

    [ConditionalFact(nameof(Available))]
    public void Unwrap_AppliesSecureDefaults()
    {
        RequireAesKeyWrapPad();
        WrapUnwrapKeyTestCases.Assert_Unwrap_AppliesSecureDefaults(_backend);
    }

    [ConditionalFact(nameof(Available))]
    public void Unwrap_ExplicitExtractable_IsAllowed()
    {
        RequireAesKeyWrapPad();
        WrapUnwrapKeyTestCases.Assert_Unwrap_ExplicitExtractable_IsAllowed(_backend);
    }
}
