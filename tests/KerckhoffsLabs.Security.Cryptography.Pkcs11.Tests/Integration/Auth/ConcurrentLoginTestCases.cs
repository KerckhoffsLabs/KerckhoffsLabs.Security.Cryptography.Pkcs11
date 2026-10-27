using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// Several logged-in sessions on one token at once. PKCS#11 keeps the login state per application and token,
/// not per session (v3.2 §5.6, <c>C_Login</c>/<c>C_Logout</c>): a second <c>C_Login</c> answers
/// CKR_USER_ALREADY_LOGGED_IN, and one <c>C_Logout</c> logs every session out. Kryoptic made that explicit in
/// 8fdd5af ("login applies to all sessions") and 238dc4d (closing the last session logs out).
/// </summary>
internal static class ConcurrentLoginTestCases
{
    private static void RequireLogin(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token needs no login.");
    }

    // A second session opened with the PIN while the first is still open is logged in too.
    internal static void Assert_SecondSessionWithPin_WhileFirstIsOpen_Opens(IPkcs11Backend backend)
    {
        RequireLogin(backend);
        using var first = backend.OpenSession();
        using var second = backend.OpenSession();

        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, first.GetSessionInfo().State);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, second.GetSessionInfo().State);
    }

    // Disposing one logged-in session must not log out another that is still in use: a private key the
    // remaining session holds keeps signing.
    internal static void Assert_DisposingOneSession_LeavesTheOtherLoggedIn(IPkcs11Backend backend)
    {
        RequireLogin(backend);
        backend.RequireMechanism(CKM.CKM_SHA256_HMAC);
        var first = backend.OpenSession();
        using var second = backend.OpenSession();
        string label = $"login-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).ValueLen(32).Sign().Verify().Attribute(CKA.CKA_PRIVATE, true).OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = second.GenerateKey(new Mechanism(CKM.CKM_GENERIC_SECRET_KEY_GEN), t);
        }
        try
        {
            first.Dispose();

            Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, second.GetSessionInfo().State);
            using var key = second.OpenKey(label);
            Assert.Equal(32, key.Sign(new Mechanism(CKM.CKM_SHA256_HMAC), "still logged in"u8).Length);
        }
        finally
        {
            using var filter = ObjectTemplate.Empty().Label(label).Build();
            foreach (var k in second.FindKeys(filter))
            {
                k.Destroy();
                k.Dispose();
            }
        }
    }

    // Once the last logged-in session is gone the token is logged out: a new session without a PIN is public.
    // BouncyHsm reports that session as read-only, so either public state passes.
    internal static void Assert_DisposingTheLastSession_LogsOut(IPkcs11Backend backend)
    {
        RequireLogin(backend);
        var first = backend.OpenSession();
        var second = backend.OpenSession();
        first.Dispose();
        second.Dispose();

        using var probe = backend.Library.OpenSessionWithoutLogin(backend.TokenLabel);
        Assert.Contains(probe.GetSessionInfo().State, (CKS[])[CKS.CKS_RW_PUBLIC_SESSION, CKS.CKS_RO_PUBLIC_SESSION]);
    }
}
