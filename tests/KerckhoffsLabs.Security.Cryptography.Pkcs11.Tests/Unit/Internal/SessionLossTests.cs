using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A session the module says is gone stops sending its number. After <c>CKR_SESSION_CLOSED</c> or
/// <c>CKR_SESSION_HANDLE_INVALID</c> the module may give that number to a session opened since; a late
/// <c>C_Logout</c> through it would log out every session the application has on the token, and a late
/// <c>C_CloseSession</c> would close someone else's session.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class SessionLossTests
{
    private const ulong Number = 7;

    /// <summary>
    /// One token, with the sessions it considers open. A call on a number it does not hold answers
    /// <see cref="DeadAnswer"/>; <see cref="Fail"/> makes the next call on a live session fail with a given code.
    /// </summary>
    private sealed class Token : SessionTestModule
    {
        public HashSet<ulong> Open { get; } = [Number];

        public bool LoggedIn { get; private set; } = true;

        public CKR DeadAnswer { get; set; } = CKR.CKR_SESSION_HANDLE_INVALID;

        public CKR? Fail { get; set; }

        public List<ulong> Closed { get; } = [];

        private CKR Answer(NativeCULong session)
        {
            if (!Open.Contains((ulong)session))
                return DeadAnswer;
            if (Fail is { } rv)
            {
                Fail = null;
                return rv;
            }
            return CKR.CKR_OK;
        }

        protected override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData) => Answer(session);

        protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) =>
            Open.Contains((ulong)session) ? CKR.CKR_OK : DeadAnswer;

        protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) =>
            Answer(session);

        protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_OK;

        protected override CKR C_Logout(NativeCULong session)
        {
            if (!Open.Contains((ulong)session))
                return DeadAnswer;
            LoggedIn = false;
            return CKR.CKR_OK;
        }

        protected override CKR C_CloseSession(NativeCULong session)
        {
            Closed.Add((ulong)session);
            return Open.Remove((ulong)session) ? CKR.CKR_OK : DeadAnswer;
        }
    }

    private static void Random(Pkcs11SessionCore session) => session.GenerateRandom(new byte[16]);

    // The lead case: the module drops session 7 and hands 7 to a new session. Disposing the old wrapper
    // must reach neither C_Logout (token-wide) nor C_CloseSession(7), which would hit the new session.
    [Fact]
    public void LostSession_WhoseNumberIsReused_IsDisposedWithoutTouchingTheNewSession()
    {
        using var token = new Token();
        Pkcs11SessionCore old = token.CreateSession(sessionId: Number);
        token.Open.Remove(Number);

        var ex = Assert.Throws<Pkcs11SessionException>(() => Random(old));
        Assert.Equal(CKR.CKR_SESSION_HANDLE_INVALID, ex.ReturnValue);

        token.Open.Add(Number);
        using Pkcs11SessionCore reopened = token.CreateSession(sessionId: Number);
        Assert.Throws<Pkcs11SessionException>(old.SendLogout); // as a login's anchor would send it
        old.Dispose();

        Assert.Equal(0, token.CallCount("C_Logout"));
        Assert.Empty(token.Closed);
        Assert.True(token.LoggedIn);
        Random(reopened);
    }

    [Theory]
    [InlineData(CKR.CKR_SESSION_CLOSED)]
    [InlineData(CKR.CKR_SESSION_HANDLE_INVALID)]
    public void SessionClosedByTheModule_RefusesLaterCalls_AndIsDisposedWithoutLogoutOrClose(CKR rv)
    {
        using var token = new Token { Fail = rv };
        Pkcs11SessionCore session = token.CreateSession(sessionId: Number);

        Assert.Equal(rv, Assert.Throws<Pkcs11SessionException>(() => Random(session)).ReturnValue);
        var later = Assert.Throws<Pkcs11SessionException>(() => Random(session));
        session.Dispose();

        Assert.Equal(rv, later.ReturnValue);
        Assert.Contains("Open a new session", later.Message, StringComparison.Ordinal);
        Assert.Equal(1, token.CallCount("C_GenerateRandom"));
        Assert.Equal(0, token.CallCount("C_Logout"));
        Assert.Empty(token.Closed);
    }

    // These do not say the module closed the session, and a network HSM can answer them transiently: the
    // session is closed once, at once, so it cannot stay open and logged in, but never logged out through.
    [Theory]
    [InlineData(CKR.CKR_DEVICE_REMOVED)]
    [InlineData(CKR.CKR_TOKEN_NOT_PRESENT)]
    public void TokenGone_ClosesTheSessionOnceAtOnce_RefusesLaterCalls_AndNeverLogsOut(CKR rv)
    {
        using var token = new Token { Fail = rv };
        Pkcs11SessionCore session = token.CreateSession(sessionId: Number);

        Assert.Equal(rv, Assert.Throws<Pkcs11TokenException>(() => Random(session)).ReturnValue);
        Assert.Equal([Number], token.Closed);

        Assert.Equal(rv, Assert.Throws<Pkcs11TokenException>(() => Random(session)).ReturnValue);
        session.Dispose();

        Assert.Equal(1, token.CallCount("C_GenerateRandom"));
        Assert.Equal(0, token.CallCount("C_Logout"));
        Assert.Equal([Number], token.Closed);
    }

    [Theory]
    [InlineData(CKR.CKR_DEVICE_ERROR)]
    [InlineData(CKR.CKR_FUNCTION_FAILED)]
    [InlineData(CKR.CKR_GENERAL_ERROR)]
    public void OtherFailures_LeaveTheSessionInUse_AndItsDisposalCloses(CKR rv)
    {
        using var token = new Token { Fail = rv };
        Pkcs11SessionCore session = token.CreateSession(sessionId: Number);

        Assert.Equal(rv, Assert.ThrowsAny<Pkcs11Exception>(() => Random(session)).ReturnValue);
        Random(session);
        session.Dispose();

        Assert.Equal(0, token.CallCount("C_Logout"));
        Assert.Equal([Number], token.Closed);
    }

    // The session or its token is lost between C_SignInit and C_Sign (BL-052). The caller sees the module's code;
    // the abandoned operation's cleanup sends no C_SessionCancel to a session that is gone; the session lock is
    // released, so the next call gets the loss rather than a concurrent-use error; and teardown sends no logout,
    // closing only a session the module did not say it had closed, and only once.
    [Theory]
    [InlineData(CKR.CKR_SESSION_CLOSED)]
    [InlineData(CKR.CKR_DEVICE_REMOVED)]
    public void SessionLostMidOperation_KeepsTheModulesCode_CancelsNothing_AndTearsDownCleanly(CKR rv)
    {
        using var token = new Token { Fail = rv };
        Pkcs11SessionCore session = token.CreateSession(sessionId: Number);
        void Sign() => session.Sign(new Mechanism(CKM.CKM_ECDSA_SHA256), new ObjectHandle(5UL), [1, 2, 3]);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(Sign);
        var later = Assert.ThrowsAny<Pkcs11Exception>(Sign);
        session.Dispose();

        Assert.Equal(rv, ex.ReturnValue);
        Assert.Equal(rv, later.ReturnValue);
        Assert.Equal(1, token.CallCount("C_SignInit"));
        Assert.Equal(0, token.CallCount("C_SessionCancel"));
        Assert.Equal(0, token.CallCount("C_Logout"));
        List<ulong> closed = rv == CKR.CKR_DEVICE_REMOVED ? [Number] : [];
        Assert.Equal(closed, token.Closed);
    }
}
