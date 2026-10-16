using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>Cross-backend port of the SoftHSM2 key wrap/unwrap integration tests, run against Kryoptic.
/// Each case runs across every <see cref="CKM"/> AES key-wrap variant and skips the ones Kryoptic
/// doesn't advertise: Kryoptic implements <see cref="CKM.CKM_AES_KEY_WRAP"/>,
/// <see cref="CKM.CKM_AES_KEY_WRAP_KWP"/> (NIST SP800-38F), and <see cref="CKM.CKM_AES_KEY_WRAP_PKCS7"/>
/// (added in the commit range picked up after 1.5.2), but never the legacy
/// <see cref="CKM.CKM_AES_KEY_WRAP_PAD"/>.</summary>
[Collection("Kryoptic")]
public sealed class WrapUnwrapKeyTests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void AesKeyWrap_RoundTrip(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        WrapUnwrapKeyTestCases.Assert_AesKeyWrap_RoundTrip(_backend, wrapMechanism);
    }

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void Unwrap_AppliesSecureDefaults(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        WrapUnwrapKeyTestCases.Assert_Unwrap_AppliesSecureDefaults(_backend, wrapMechanism);
    }

    [Theory(SkipUnless = nameof(KryopticBackendFixture.KryopticAvailable), SkipType = typeof(KryopticBackendFixture), Skip = "Requires " + nameof(KryopticBackendFixture.KryopticAvailable))]
    [InlineData(CKM.CKM_AES_KEY_WRAP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PAD)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_KWP)]
    [InlineData(CKM.CKM_AES_KEY_WRAP_PKCS7)]
    public void Unwrap_ExplicitExtractable_IsAllowed(CKM wrapMechanism)
    {
        _backend.RequireMechanism(wrapMechanism);
        WrapUnwrapKeyTestCases.Assert_Unwrap_ExplicitExtractable_IsAllowed(_backend, wrapMechanism);
    }
}
