using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// FreeHSM integration for <c>Pkcs11Session.SetPinWithPin</c>. Unlike the other backends' round trip,
/// this pins what FreeHSM does: its <c>C_SetPIN</c> refuses a session that is not logged in
/// (<c>CKR_USER_NOT_LOGGED_IN</c>) and then verifies the old PIN through its login path, which answers
/// <c>CKR_USER_ALREADY_LOGGED_IN</c> for the session's own user before it looks at the PIN. So no call can
/// change a PIN. PKCS#11 allows <c>C_SetPIN</c> in a logged-in R/W session. When a fix upstream makes the
/// change succeed, this fails and the round trip the other backends run can take over.
/// </summary>
[Collection("FreeHsm")]
public sealed class PinManagementTests_FreeHsm(FreeHsmBackendFixture f)
{
    private readonly FreeHsmBackendFixture _backend = f;

    [Fact(SkipUnless = nameof(FreeHsmBackendFixture.FreeHsmAvailable), SkipType = typeof(FreeHsmBackendFixture), Skip = "Requires " + nameof(FreeHsmBackendFixture.FreeHsmAvailable))]
    public void SetPinWithPin_InALoggedInSession_IsRefused_PinUnchanged()
    {
        byte[] original = _backend.UserPin.ToArray();
        byte[] temp = Encoding.UTF8.GetBytes("87654321");

        using (var session = _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(original)))
        {
            Exception? ex;
            using (var o = new SecurePin(original))
            using (var n = new SecurePin(temp))
                ex = Record.Exception(() => session.SetPinWithPin(o, n));

            if (ex is null)
            {
                // Fixed upstream: put the shared token's PIN back before failing.
                using var o = new SecurePin(temp);
                using var n = new SecurePin(original);
                session.SetPinWithPin(o, n);
                Assert.Fail("C_SetPIN changed the PIN; run the round trip the other backends run.");
            }

            var refused = Assert.IsType<Pkcs11AuthenticationException>(ex);
            Assert.Equal(CKR.CKR_USER_ALREADY_LOGGED_IN, refused.ReturnValue);
        }

        // The original PIN still logs in.
        using var again = _backend.Library.OpenSessionWithPin(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(original));
    }
}
