using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Curve25519 private-key wrapping over NSS -- thin wrapper over
/// <see cref="WrapUnwrapCurve25519TestCases"/>. Softoken packs a wrapped private key as PKCS#8, and
/// before 3.131 it had no PKCS#8 form for either curve: <c>C_WrapKey</c> and <c>C_UnwrapKey</c> both
/// failed. 3.131 (Bug 1993638) encodes them as RFC 8410 specifies. The mechanism list is the same
/// before and after 3.131, so the cases are gated on the softoken release.
/// </summary>
[Collection("Nss")]
public sealed class WrapUnwrapCurve25519Tests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    private const string Rfc8410Pkcs8 = "PKCS#8 for Ed25519 and X25519 private keys arrived in 3.131 (Bug 1993638)";

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_Rfc8410Ed25519Key_SignsTheRfc8032Signature()
    {
        _backend.RequireSoftoken(3, 131, Rfc8410Pkcs8);
        WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc8410Ed25519Key_SignsTheRfc8032Signature(_backend);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_Rfc5958Ed25519KeyWithOptionalFields_SignsTheRfc8032Signature()
    {
        _backend.RequireSoftoken(3, 131, Rfc8410Pkcs8);
        WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc5958Ed25519KeyWithOptionalFields_SignsTheRfc8032Signature(_backend);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret()
    {
        _backend.RequireSoftoken(3, 131, Rfc8410Pkcs8);
        WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret(_backend);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void WrapUnwrap_Ed25519PrivateKey_KeepsTheKey()
    {
        _backend.RequireSoftoken(3, 131, Rfc8410Pkcs8);
        WrapUnwrapCurve25519TestCases.Assert_WrapUnwrap_Ed25519PrivateKey_KeepsTheKey(_backend);
    }

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal()
    {
        _backend.RequireSoftoken(3, 131, Rfc8410Pkcs8);
        WrapUnwrapCurve25519TestCases.Assert_WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal(_backend);
    }
}
