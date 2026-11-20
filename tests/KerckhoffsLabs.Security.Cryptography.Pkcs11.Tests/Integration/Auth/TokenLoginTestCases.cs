using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Auth;

/// <summary>
/// The token login model on real modules: a login belongs to the application and the token, and every session the
/// application has with the token shares it (PKCS#11 v3.2 §5.6, "Session management functions"). A
/// <see cref="Pkcs11Login"/> and the sessions it opens hold it; disposing any of them, in any order, logs out only
/// when the last one goes.
/// </summary>
/// <remarks>
/// <para>
/// Every case signs with a private key (<c>CKA_PRIVATE = TRUE</c>), which only a logged-in session may use, so a
/// logout that came too early fails the case at the module (<c>CKR_USER_NOT_LOGGED_IN</c>, or a handle the logout
/// invalidated) or at the library (a private key refused once its login has ended).
/// </para>
/// <para>
/// Each session signs with a key of its own rather than one another session made: a session object is the
/// application's (§5.6.2), but wolfPKCS11 keeps it to its session
/// (<see cref="WolfPkcs11BackendFixture.WolfPkcs11SharesSessionObjectsAcrossSessions"/>), and sharing objects is not
/// what these cases test. A login keeps a session of its own (its anchor) besides the ones it opens, so the cases that
/// need two working sessions at once cannot run on a token that allows one session at a time (pkcs11-mock); the
/// <c>Assert_OneSessionToken_*</c> cases are the ones written for it.
/// </para>
/// </remarks>
internal static class TokenLoginTestCases
{
    private static readonly byte[] Digest = SHA256.HashData("token login"u8);

    private static Pkcs11Slot Slot(IPkcs11Backend backend)
        => backend.Library.GetSlotList().First(s => (NativeCULong)s.SlotId.Value == backend.SlotId);

    private static Pkcs11Login LogIn(IPkcs11Backend backend)
    {
        using var pin = new SecurePin(backend.UserPin.Span);
        return Slot(backend).Login(TokenUser.User, pin);
    }

    private static void RequireLoginAndEcdsa(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token has no login.");
        backend.RequireMechanisms(CKM.CKM_EC_KEY_PAIR_GEN, CKM.CKM_ECDSA);
    }

    // A private P-256 signing key of the session's own: a session object, or a token object on a token that makes
    // key pairs only on the token (tpm2-pkcs11), which the caller destroys.
    private static Pkcs11Key NewSigningKey(Pkcs11Session session, bool tokenKeys)
        => session.GenerateEcSigningKeyPair(label: $"kl-login-{Guid.NewGuid():N}", persistOnToken: tokenKeys);

    private static void AssertSigns(Pkcs11Key key)
    {
        var ecdsa = new Mechanism(CKM.CKM_ECDSA);
        byte[] signature = key.Sign(ecdsa, Digest);
        Assert.True(key.Verify(ecdsa, Digest, signature));
    }

    /// <summary>
    /// Two sessions under one login are both in the "R/W User Functions" state, and both sign with a private key:
    /// the second session needs no login of its own (§5.6: "C_Login only needs to be called for one of the
    /// sessions"), and opening it does not disturb the first.
    /// </summary>
    internal static void Assert_TwoSessionsUnderOneLogin_BothSignWithAPrivateKey(IPkcs11Backend backend, bool tokenKeys = false)
    {
        RequireLoginAndEcdsa(backend);

        using Pkcs11Login login = LogIn(backend);
        using Pkcs11Session first = login.OpenSession();
        using Pkcs11Session second = login.OpenSession();

        foreach (Pkcs11LoginInfo? info in new[] { first.LoginInfo, second.LoginInfo })
        {
            Assert.NotNull(info);
            Assert.Equal(login.Slot.SlotId, info.Slot.SlotId);
            Assert.Equal(login.User, info.User);
            Assert.True(info.IsActive);
        }
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, first.GetSessionInfo().State);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, second.GetSessionInfo().State);

        using Pkcs11Key firstKey = NewSigningKey(first, tokenKeys);
        using Pkcs11Key secondKey = NewSigningKey(second, tokenKeys);
        try
        {
            AssertSigns(firstKey);
            AssertSigns(secondKey);
            AssertSigns(firstKey);
        }
        finally
        {
            firstKey.Destroy();
            secondKey.Destroy();
        }
    }

    /// <summary>
    /// Disposing one session of a login closes that session only: it never sends <c>C_Logout</c> while another
    /// holder remains, so the other session stays logged in and keeps signing with its private key.
    /// </summary>
    internal static void Assert_DisposingOneSession_OtherKeepsSigning(IPkcs11Backend backend, bool tokenKeys = false)
    {
        RequireLoginAndEcdsa(backend);

        using Pkcs11Login login = LogIn(backend);
        using Pkcs11Session survivor = login.OpenSession();
        using Pkcs11Key key = NewSigningKey(survivor, tokenKeys);
        try
        {
            AssertSigns(key);

            using Pkcs11Session disposed = login.OpenSession();
            disposed.Dispose();

            Assert.True(login.IsActive);
            Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, survivor.GetSessionInfo().State);
            AssertSigns(key);
        }
        finally
        {
            key.Destroy();
        }
    }

    /// <summary>
    /// Disposing the <see cref="Pkcs11Login"/> first does not log out: the sessions it opened hold the login too, and
    /// keep signing until the last of them is disposed, which logs the token out. A session opened afterwards is
    /// public.
    /// </summary>
    internal static void Assert_DisposingTheLogin_SessionsKeepWorkingUntilLastCloses(IPkcs11Backend backend, bool tokenKeys = false)
    {
        RequireLoginAndEcdsa(backend);

        // Everything is disposed, in the test's own order, before the block ends; the using declarations only
        // close what a failure partway left open (Dispose is idempotent). A key not yet destroyed is destroyed on
        // the way out, so a token key (tokenKeys) never stays on the token; a session key would go with its session.
        {
            using Pkcs11Login login = LogIn(backend);
            using Pkcs11Session first = login.OpenSession();
            using Pkcs11Session second = login.OpenSession();
            bool firstDestroyed = false;
            bool secondDestroyed = false;
            using Pkcs11Key firstKey = NewSigningKey(first, tokenKeys);
            try
            {
                using Pkcs11Key secondKey = NewSigningKey(second, tokenKeys);
                try
                {
                    login.Dispose();
                    Assert.False(login.IsActive); // this hold is released; the sessions' holds keep the login

                    AssertSigns(firstKey);
                    AssertSigns(secondKey);

                    firstKey.Destroy();
                    firstDestroyed = true;
                    firstKey.Dispose();
                    first.Dispose();

                    Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, second.GetSessionInfo().State);
                    AssertSigns(secondKey);

                    secondKey.Destroy();
                    secondDestroyed = true;
                    secondKey.Dispose();
                    second.Dispose();
                }
                finally
                {
                    if (!secondDestroyed)
                        secondKey.Destroy();
                }
            }
            finally
            {
                if (!firstDestroyed)
                    firstKey.Destroy();
            }
        }

        using Pkcs11Session after = Slot(backend).OpenSession(SessionAccess.ReadOnly);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, after.GetSessionInfo().State);
    }

    /// <summary>
    /// A session from <see cref="Pkcs11Slot.OpenSession"/> holds no login but sees the application's (§5.6): it is in
    /// "R/O User Functions" while a login is held, and drops to "R/O Public Session" when the last holder goes, while
    /// it stays open.
    /// </summary>
    internal static void Assert_AfterLastHolder_SlotSessionIsPublic(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token has no login.");

        using Pkcs11Session observer = Slot(backend).OpenSession(SessionAccess.ReadOnly);
        Assert.Null(observer.LoginInfo);
        Assert.Equal(SessionAccess.ReadOnly, observer.Access);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, observer.GetSessionInfo().State);

        // The login and its session are both disposed when the block ends, the login first.
        {
            using Pkcs11Login login = LogIn(backend);
            using Pkcs11Session session = login.OpenSession();
            Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, observer.GetSessionInfo().State);

            login.Dispose();
            Assert.Equal(CKS.CKS_RO_USER_FUNCTIONS, observer.GetSessionInfo().State); // the session still holds it
        }

        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, observer.GetSessionInfo().State);
    }

    // === Tokens that allow one session: the login lends its own ============================================

    // CKR_SESSION_COUNT, with the library's explanation: each key phrase (stable words, not whole sentences).
    private static Pkcs11SessionException AssertSessionCountRefused(Action open, params string[] keyPhrases)
    {
        var ex = Assert.ThrowsAny<Pkcs11SessionException>(open);
        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        foreach (string phrase in keyPhrases)
            Assert.Contains(phrase, ex.Message, StringComparison.Ordinal);
        return ex;
    }

    /// <summary>On a token that allows one session, <see cref="Pkcs11Login.OpenSession()"/> lends the login's own
    /// session: read/write, in "R/W User Functions".</summary>
    internal static void Assert_OneSessionToken_LoginLendsItsSession(IPkcs11Backend backend)
    {
        using Pkcs11Login login = LogIn(backend);
        using Pkcs11Session session = login.OpenSession();

        Assert.Equal(login.User, session.LoginInfo!.User);
        Assert.True(session.IsLent);
        Assert.Equal(SessionAccess.ReadWrite, session.Access);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, session.GetSessionInfo().State);
    }

    /// <summary>A second session is refused with <c>CKR_SESSION_COUNT</c> while the first is lent; the first keeps
    /// working.</summary>
    internal static void Assert_OneSessionToken_SecondSessionRefused_WhileLent(IPkcs11Backend backend)
    {
        using Pkcs11Login login = LogIn(backend);
        using Pkcs11Session first = login.OpenSession();

        AssertSessionCountRefused(() => login.OpenSession(), "lent", "Dispose that session first");
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, first.GetSessionInfo().State);
    }

    /// <summary>Disposing the lent session hands it back, and the login lends it again.</summary>
    internal static void Assert_OneSessionToken_DisposedSessionIsLentAgain(IPkcs11Backend backend)
    {
        using Pkcs11Login login = LogIn(backend);
        login.OpenSession().Dispose();

        using Pkcs11Session again = login.OpenSession();
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, again.GetSessionInfo().State);
    }

    /// <summary>Once the lent session and the login are both disposed the login's session closes, the token is free,
    /// and a slot session opens read-only in "R/O Public Session".</summary>
    internal static void Assert_OneSessionToken_LastHolderFreesTheToken(IPkcs11Backend backend)
    {
        // The login and the lent session are both disposed when the block ends, the login first.
        {
            using Pkcs11Login login = LogIn(backend);
            using Pkcs11Session session = login.OpenSession();
            login.Dispose();
            Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, session.GetSessionInfo().State); // the session still holds it
        }

        using Pkcs11Session slotSession = Slot(backend).OpenSession(SessionAccess.ReadOnly);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, slotSession.GetSessionInfo().State);
    }

    /// <summary>While a login holds the token's only session, <see cref="Pkcs11Slot.OpenSession"/> fails with
    /// <c>CKR_SESSION_COUNT</c>.</summary>
    internal static void Assert_OneSessionToken_SlotSessionRefusedWhileLoggedIn(IPkcs11Backend backend)
    {
        using Pkcs11Login login = LogIn(backend);

        AssertSessionCountRefused(() => Slot(backend).OpenSession(SessionAccess.ReadOnly), "login on it keeps a session of its own",
            "Pkcs11Login.OpenSession");
    }

    /// <summary>While a slot session holds the token's only session, a <see cref="Pkcs11Slot.Login(TokenUser, SecurePin)"/> fails with
    /// <c>CKR_SESSION_COUNT</c>, and works once the session is disposed.</summary>
    internal static void Assert_OneSessionToken_LoginRefusedWhileSlotSessionOpen(IPkcs11Backend backend)
    {
        using (Pkcs11Session slotSession = Slot(backend).OpenSession(SessionAccess.ReadOnly))
            AssertSessionCountRefused(() => LogIn(backend), "a login needs a session of its own", "log in first",
                "Pkcs11Login.OpenSession");

        using Pkcs11Login login = LogIn(backend);
        Assert.True(login.IsActive);
    }

    /// <summary>
    /// A write-protected token (<c>CKF_WRITE_PROTECTED</c>): a read/write session is either refused by the module
    /// (<c>CKR_TOKEN_WRITE_PROTECTED</c>, leaving no session open) or opened, as NSS does, with the access the module
    /// reports; and a read-only one opens and makes and uses session objects: PKCS#11 v3.2 §5.7.1 keeps only token objects
    /// out of a read-only session.
    /// </summary>
    internal static void Assert_WriteProtectedToken_OpensReadOnly(IPkcs11Backend backend)
    {
        Pkcs11Slot slot = Slot(backend);
        Assert.True(slot.GetTokenInfo().TokenFlags.WriteProtected, "The fixture's token is expected to be write-protected.");
        backend.RequireMechanism(CKM.CKM_AES_KEY_GEN);

        ulong before = slot.GetTokenInfo().SessionCount;
        try
        {
            using Pkcs11Session readWrite = slot.OpenSession(SessionAccess.ReadWrite);
            // Opened (NSS): the access recorded is the one the module reports.
            Assert.Equal(readWrite.GetSessionInfo().SessionFlags.RwSession, readWrite.Access == SessionAccess.ReadWrite);
        }
        catch (Pkcs11Exception refused)
        {
            Assert.Equal(CKR.CKR_TOKEN_WRITE_PROTECTED, refused.ReturnValue);
        }
        Assert.Equal(before, slot.GetTokenInfo().SessionCount); // no session left open

        using Pkcs11Session session = slot.OpenSession(SessionAccess.ReadOnly);
        Assert.Equal(SessionAccess.ReadOnly, session.Access);
        Assert.Null(session.LoginInfo);
        SessionInfo info = session.GetSessionInfo();
        Assert.False(info.SessionFlags.RwSession);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, info.State);

        using Pkcs11Key key = session.GenerateAesKey(label: $"kl-login-ro-{Guid.NewGuid():N}");
        try
        {
            using var attrs = key.GetAttributeValue(CKA.CKA_VALUE_LEN);
            Assert.Equal(32UL, Assert.Single(attrs).GetValueAsUlong());
        }
        finally
        {
            key.Destroy();
        }
    }

    /// <summary>
    /// A private key with <c>CKA_ALWAYS_AUTHENTICATE = TRUE</c> signs through the session's
    /// <see cref="ContextAuthentication"/>: the library sends <c>C_Login(CKU_CONTEXT_SPECIFIC)</c> after
    /// <c>C_SignInit</c>, asking for the PIN once per operation, and a session with no source refuses the key before
    /// the operation starts.
    /// </summary>
    /// <param name="backend">The backend whose token makes the key.</param>
    /// <param name="tokenKeys">Make the key pair token objects, on a token that makes key pairs only on the token.</param>
    /// <param name="tokenMarksTheKey">
    /// Leave <c>CKA_ALWAYS_AUTHENTICATE</c> out of the template, on a token that sets it itself on a private, sign-only,
    /// sensitive and not extractable key (the template's defaults) and refuses it in a template (BouncyHsm's
    /// qualified area). The case still asserts the key has it.
    /// </param>
    /// <param name="contextPin">The PIN the token's context login takes; <see langword="null"/> for the user PIN.</param>
    internal static void Assert_AlwaysAuthenticateKey_SignsWithContextLogin(IPkcs11Backend backend, bool tokenKeys = false,
        bool tokenMarksTheKey = false, ReadOnlyMemory<byte>? contextPin = null)
    {
        RequireLoginAndEcdsa(backend);

        using Pkcs11Login login = LogIn(backend);
        using Pkcs11Session session = login.OpenSession();

        string label = $"kl-login-aa-{Guid.NewGuid():N}";
        byte[] id = TestKeys.IdFor(label);
        using var publicTemplate = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Verify()
            .Label(label).Id(id).OnToken(tokenKeys).Build();
        PrivateKeyTemplateBuilder privateBuilder = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Sign();
        if (!tokenMarksTheKey)
            privateBuilder = privateBuilder.Attribute(CKA.CKA_ALWAYS_AUTHENTICATE, true);
        using var privateTemplate = privateBuilder.Label(label).Id(id).OnToken(tokenKeys).Build();
        using Pkcs11Key key = session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicTemplate, privateTemplate);
        try
        {
            Assert.True(key.AlwaysAuthenticate);

            var ecdsa = new Mechanism(CKM.CKM_ECDSA);
            Assert.Null(session.ContextAuthentication);
            Assert.Throws<InvalidOperationException>(() => key.Sign(ecdsa, Digest));

            int asked = 0;
            Pkcs11Key? askedFor = null;
            session.ContextAuthentication = ContextAuthentication.FromPinSource(k =>
            {
                askedFor = k;
                asked++;
                return new SecurePin((contextPin ?? backend.UserPin).Span);
            });

            byte[] first = key.Sign(ecdsa, Digest);
            Assert.Equal(1, asked);
            Assert.Same(key, askedFor);
            byte[] second = key.Sign(ecdsa, Digest);
            Assert.Equal(2, asked);

            Assert.True(key.Verify(ecdsa, Digest, first));
            Assert.True(key.Verify(ecdsa, Digest, second));
            Assert.Equal(2, asked); // verifying uses the public key, which asks for nothing
            Assert.True(login.IsActive);

            // The PIN asked for shows the library's flow ran, not that the module checked it: tell a module that
            // enforces the attribute (both context logins accepted) from one that ignores it (CKR_OPERATION_NOT_INITIALIZED),
            // which this case cannot then vouch for.
            (int accepted, int notNeeded) = session.Core.ContextLogins;
            Assert.Equal(2, accepted + notNeeded);
            if (notNeeded > 0)
            {
                Assert.Skip("The module answered the context login CKR_OPERATION_NOT_INITIALIZED: it does not enforce " +
                    "CKA_ALWAYS_AUTHENTICATE, so only the library's side of the flow was checked.");
            }
            Assert.Equal(2, accepted);
        }
        finally
        {
            key.Destroy();
        }
    }

    /// <summary>
    /// A private key used after its login ended: the key belongs to a slot session (which holds no login), and once
    /// the last holder logs out, PKCS#11 v3.2 <c>C_Logout</c> has invalidated its handle. The library refuses it with
    /// <see cref="Pkcs11LoginEndedException"/> before the handle reaches the module, which may since have given it to
    /// another object.
    /// </summary>
    internal static void Assert_PrivateKeyAfterTheLoginEnded_RefusedWithLoginEnded(IPkcs11Backend backend)
    {
        RequireLoginAndEcdsa(backend);

        Pkcs11Login login = LogIn(backend);
        using Pkcs11Session session = Slot(backend).OpenSession(SessionAccess.ReadWrite);
        using Pkcs11Key key = NewSigningKey(session, tokenKeys: false);
        AssertSigns(key);

        login.Dispose();

        var ex = Assert.Throws<Pkcs11LoginEndedException>(() => key.Sign(new Mechanism(CKM.CKM_ECDSA), Digest));
        Assert.Equal(CKR.CKR_USER_NOT_LOGGED_IN, ex.ReturnValue);
        Assert.IsAssignableFrom<Pkcs11AuthenticationException>(ex);
    }

    /// <summary>
    /// A wrong PIN on a real token: the module refuses it (one retry spent, whichever refusal code it answers), and the
    /// same PIN is then refused before the module, by the library; the right PIN logs in, which resets the token's
    /// count. The wrong PIN differs from the fixture's in its last byte only, so a module that checks the length first
    /// still compares it.
    /// </summary>
    internal static void Assert_WrongPin_SentOnce_ThenRefusedBeforeTheModule(IPkcs11Backend backend)
    {
        if (!backend.RequiresUserLogin)
            Assert.Skip("The backend's token has no login.");
        Pkcs11Slot slot = Slot(backend);
        byte[] wrongBytes = backend.UserPin.ToArray();
        wrongBytes[^1] = (byte)(wrongBytes[^1] == (byte)'0' ? '1' : '0');
        using var wrong = new SecurePin(wrongBytes);
        // A refusal another test left (they are kept for the process) would refuse the first attempt before the module.
        slot.ForgetRefusedPins();
        try
        {
            var first = Assert.ThrowsAny<Pkcs11AuthenticationException>(() => slot.Login(TokenUser.User, wrong));
            Assert.DoesNotContain("refused this PIN before", first.Message, StringComparison.Ordinal);

            var second = Assert.ThrowsAny<Pkcs11AuthenticationException>(() => slot.Login(TokenUser.User, wrong));
            Assert.Equal(CKR.CKR_PIN_INCORRECT, second.ReturnValue);
            Assert.Contains("refused this PIN before", second.Message, StringComparison.Ordinal);

            using Pkcs11Login login = LogIn(backend);
            Assert.True(login.IsActive);
        }
        finally
        {
            // The refusal is kept for the process: other tests on this token must not inherit it.
            slot.ForgetRefusedPins();
        }
    }
}
