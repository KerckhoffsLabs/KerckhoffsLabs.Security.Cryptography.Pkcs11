using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Curve25519 private-key wrapping over Craton HSM -- thin wrapper over
/// <see cref="WrapUnwrapCurve25519TestCases"/>. Every case skips at run time: Craton lists
/// <c>CKM_AES_CBC_PAD</c>, the wrap the cases use, for encryption only, and has no X25519.
/// </summary>
[Collection("CratonHsm")]
public sealed class WrapUnwrapCurve25519Tests_CratonHsm(CratonHsmBackendFixture backend)
{
    private readonly CratonHsmBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Unwrap_Rfc8410Ed25519Key_SignsTheRfc8032Signature() => WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc8410Ed25519Key_SignsTheRfc8032Signature(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Unwrap_Rfc5958Ed25519KeyWithOptionalFields_SignsTheRfc8032Signature() => WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc5958Ed25519KeyWithOptionalFields_SignsTheRfc8032Signature(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret() => WrapUnwrapCurve25519TestCases.Assert_Unwrap_Rfc8410X25519Key_AgreesTheRfc7748Secret(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void WrapUnwrap_Ed25519PrivateKey_KeepsTheKey() => WrapUnwrapCurve25519TestCases.Assert_WrapUnwrap_Ed25519PrivateKey_KeepsTheKey(_backend);

    [Fact(SkipUnless = nameof(CratonHsmBackendFixture.CratonHsmAvailable), SkipType = typeof(CratonHsmBackendFixture), Skip = "Requires " + nameof(CratonHsmBackendFixture.CratonHsmAvailable))]
    public void WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal() => WrapUnwrapCurve25519TestCases.Assert_WrapUnwrap_X25519PrivateKey_AgreesLikeTheOriginal(_backend);
}
