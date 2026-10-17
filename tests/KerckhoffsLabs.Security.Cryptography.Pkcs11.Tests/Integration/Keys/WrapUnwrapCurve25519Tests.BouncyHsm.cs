using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Curve25519 private-key wrapping over BouncyHsm -- thin wrapper over
/// <see cref="WrapUnwrapCurve25519TestCases"/>. Every case skips (see
/// <see cref="SupportsRfc8410PrivateKeys"/>).
/// </summary>
[Collection("BouncyHsm")]
public sealed class WrapUnwrapCurve25519Tests_BouncyHsm(BouncyHsmBackendFixture backend)
{
    private readonly BouncyHsmBackendFixture _backend = backend;

    // BouncyHsm wraps these keys as an RFC 5958 OneAsymmetricKey v2 (version 1, public key included:
    // 30 51 02 01 01 ...), which is valid, but the shared cases compare the PKCS#8 bytes with the v1
    // encoding OpenSSL, SoftHSM and NSS write (30 2E 02 01 00 ...).
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
