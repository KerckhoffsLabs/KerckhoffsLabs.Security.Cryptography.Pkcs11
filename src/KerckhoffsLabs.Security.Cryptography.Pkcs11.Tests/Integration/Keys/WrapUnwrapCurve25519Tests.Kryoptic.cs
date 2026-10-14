using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Curve25519 private-key wrapping over Kryoptic -- thin wrapper over
/// <see cref="WrapUnwrapCurve25519TestCases"/>. Every case skips: Kryoptic's PKCS#8 for these curves
/// is not RFC 8410's (see <see cref="SupportsRfc8410PrivateKeys"/>).
/// </summary>
[Collection("Kryoptic")]
public sealed class WrapUnwrapCurve25519Tests_Kryoptic(KryopticBackendFixture backend)
{
    private readonly KryopticBackendFixture _backend = backend;

    // Kryoptic's ec::export_for_wrapping (src/ec/mod.rs) puts an Edwards or Montgomery CKA_VALUE
    // straight into PrivateKeyInfo's privateKey OCTET STRING, where RFC 8410 nests it in a second one
    // (CurvePrivateKey): it wraps a 46-byte 30 2C ... 04 20 <key> where OpenSSL, SoftHSM and NSS 3.131
    // write the 48-byte 30 2E ... 04 22 04 20 <key>. import_from_wrapped mirrors it, so an RFC 8410 key
    // unwraps to a 34-byte CKA_VALUE (04 20 <key>) that C_SignInit and C_DeriveKey then refuse with
    // CKR_DEVICE_ERROR. Its own wrap and unwrap agree, so it only fails against another
    // implementation, which is what every case here is. Still so on upstream main as of 2026-10.
    public static bool SupportsRfc8410PrivateKeys => false;

    [Fact(SkipUnless = nameof(SupportsRfc8410PrivateKeys), Skip = "Requires " + nameof(SupportsRfc8410PrivateKeys))]
    public void Unwrap_Rfc8410Ed25519Key_SignsTheRfc8032Signature() => WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc8410Ed25519Key_SignsTheRfc8032Signature(_backend);

    [Fact(SkipUnless = nameof(SupportsRfc8410PrivateKeys), Skip = "Requires " + nameof(SupportsRfc8410PrivateKeys))]
    public void Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret() => WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret(_backend);

    [Fact(SkipUnless = nameof(SupportsRfc8410PrivateKeys), Skip = "Requires " + nameof(SupportsRfc8410PrivateKeys))]
    public void WrapUnwrap_Ed25519PrivateKey_KeepsTheKey() => WrapUnwrapCurve25519TestCases.Assert_WrapUnwrap_Ed25519PrivateKey_KeepsTheKey(_backend);

    [Fact(SkipUnless = nameof(SupportsRfc8410PrivateKeys), Skip = "Requires " + nameof(SupportsRfc8410PrivateKeys))]
    public void WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal() => WrapUnwrapCurve25519TestCases.Assert_WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal(_backend);
}
