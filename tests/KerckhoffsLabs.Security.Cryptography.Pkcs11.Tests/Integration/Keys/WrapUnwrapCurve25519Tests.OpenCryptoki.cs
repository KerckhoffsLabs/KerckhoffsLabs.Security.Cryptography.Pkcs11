using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Curve25519 private-key wrapping over opencryptoki's software token -- thin wrapper over
/// <see cref="WrapUnwrapCurve25519TestCases"/>. Every case skips: opencryptoki's PKCS#8 for these
/// curves is not RFC 8410's, and its unwrap refuses the template (see
/// <see cref="SupportsRfc8410PrivateKeys"/>).
/// </summary>
[Collection("OpenCryptoki")]
public sealed class WrapUnwrapCurve25519Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;

    // Two independent failures, both seen in CI against v3.27.0:
    //  - Wrapping: ber_encode_ECPrivateKey (usr/lib/common/asn1.c) encodes an Edwards or Montgomery
    //    key as an RFC 5915 ECPrivateKey, SEQUENCE { version 1, OCTET STRING key }, inside
    //    PrivateKeyInfo's privateKey, where RFC 8410 puts the bare CurvePrivateKey OCTET STRING: it
    //    wraps 30 33 ... 04 27 30 25 02 01 01 04 20 <key> where OpenSSL, SoftHSM and NSS 3.131 write
    //    30 2E ... 04 22 04 20 <key>.
    //  - Unwrapping: C_UnwrapKey refuses CKA_SENSITIVE / CKA_EXTRACTABLE in the template with
    //    CKR_ATTRIBUTE_READ_ONLY (see WrapUnwrapKeyTests_OpenCryptoki), and the library always adds
    //    them as secure defaults, so no RFC 8410 key reaches the decoder.
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
