using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Curve25519 private-key wrapping over opencryptoki's software token -- thin wrapper over
/// <see cref="WrapUnwrapCurve25519TestCases"/>. Every case skips: opencryptoki's PKCS#8 for these
/// curves is still not RFC 8410's (see <see cref="SupportsRfc8410PrivateKeys"/>).
/// </summary>
[Collection("OpenCryptoki")]
public sealed class WrapUnwrapCurve25519Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    // v3.27.0 wrapped an Edwards or Montgomery key as an RFC 5915 ECPrivateKey inside PrivateKeyInfo's
    // privateKey (https://github.com/opencryptoki/opencryptoki/issues/983). 595ca62a, in the vendored
    // commit, drops the SEQUENCE but also the CurvePrivateKey OCTET STRING RFC 8410 nests in privateKey:
    // der_encode_ECPrivateKey (usr/lib/common/asn1.c) hands the raw key to ber_encode_PrivateKeyInfo, so
    // it wraps 30 2C ... 04 20 <key> where OpenSSL, SoftHSM and NSS 3.131 write 30 2E ... 04 22 04 20 <key>,
    // and der_decode_ECPrivateKey takes privateKey's contents as CKA_VALUE, so unwrapping RFC 8410's form
    // stores the 34 bytes 04 20 <key> and fails with CKR_FUNCTION_FAILED. Both seen in CI against 1cf36153.
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
