using System.Reflection;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// A login on a token that allows the application one session (<see cref="LoginTokenModule.MaxSessions"/>): the
/// module's <c>CKR_SESSION_COUNT</c> keeps its code, and the message says why the session is refused and what to do;
/// and <see cref="Pkcs11Login.OpenSession"/>, on that answer, lends the login's own session (the anchor), one working
/// session at a time, and takes it back.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class AnchorLendingTests : IDisposable
{
    private const string SigningKey = "plain-ec";
    private const string AlwaysAuthenticateEc = "aa-ec";

    private static readonly Mechanism Ecdsa = new(CKM.CKM_ECDSA_SHA256);

    // Every wait is bounded: a lock-order regression shows as a timed-out wait, not a hung run.
    private static readonly TimeSpan Bounded = TimeSpan.FromSeconds(5);

    // How long a thread that should be blocked is watched for not having returned.
    private static readonly TimeSpan Watch = TimeSpan.FromMilliseconds(200);

    private readonly LoginTokenModule _module = new() { MaxSessions = 1 };
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public AnchorLendingTests()
    {
        _module.AddObject(CKO.CKO_PRIVATE_KEY, SigningKey, isPrivate: true, keyType: CKK.CKK_EC);
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateEc, isPrivate: true, keyType: CKK.CKK_EC,
            more: new Dictionary<CKA, byte[]> { [CKA.CKA_ALWAYS_AUTHENTICATE] = [1] });
        _library = _module.Load();
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    private TokenLoginRecord Record => TokenLoginRegistry.Of(_library.LowLevelLibrary!.Module).For((NativeCULong)LoginTokenModule.SlotId);

    private ulong AnchorId => Assert.IsType<Pkcs11SessionCore>(Record.Anchor).SessionId;

    private static void AssertLent(Pkcs11Session session, ulong anchorId) => Assert.Equal(anchorId, session.Core.SessionId);

    // Runs action on a background thread; the exception it threw, if any, is in the returned box once joined.
    private static (Thread Thread, Func<Exception?> Failure) Start(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception ex) { failure = ex; }
        })
        { IsBackground = true };
        thread.Start();
        return (thread, () => failure);
    }

    [Fact]
    public void Login_WhileSlotSessionHoldsTheOnlySession_FailsWithSessionCount_NamingTheSessions()
    {
        using Pkcs11Session slotSession = Slot.OpenSession();

        var ex = Assert.Throws<Pkcs11SessionException>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.Equal("C_OpenSession", ex.Method);
        Assert.Contains("1 session", ex.Message, StringComparison.Ordinal);
        Assert.Contains("log in first", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, _module.LoginCalls);
        Assert.Equal(CKS.CKS_RO_PUBLIC_SESSION, slotSession.GetSessionInfo().State);
        // The slot session, then the login's own: read/write refused, and the read-only fallback refused too.
        Assert.Equal([CKR.CKR_OK, CKR.CKR_SESSION_COUNT, CKR.CKR_SESSION_COUNT], _module.OpenSessionResults);
        Assert.Equal(slotSession.Core.SessionId, Assert.Single(_module.OpenSessions).Handle);
    }

    [Fact]
    public void Login_WhenTheSessionsAreNotTheLibrarys_SaysSo()
    {
        _module.MaxSessions = 0;

        var ex = Assert.Throws<Pkcs11SessionException>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.Contains("not opened through this library", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, _module.LoginCalls);
    }

    [Fact]
    public void SlotOpenSession_WhileLoggedIn_OnOneSessionToken_FailsNamingTheLogin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        var ex = Assert.Throws<Pkcs11SessionException>(() => Slot.OpenSession());

        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.Equal("C_OpenSession", ex.Method);
        Assert.Contains("Pkcs11Login.OpenSession", ex.Message, StringComparison.Ordinal);
        Assert.True(login.IsActive);
        Assert.Single(_module.OpenSessions);
    }

    [Fact]
    public void SlotOpenSession_SessionCount_WithoutLogin_KeepsModuleMessage()
    {
        using Pkcs11Session first = Slot.OpenSession();

        var ex = Assert.Throws<Pkcs11SessionException>(() => Slot.OpenSession());

        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.DoesNotContain("login", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Pkcs11Exception.Create(CKR.CKR_SESSION_COUNT, "C_OpenSession").Message, ex.Message);
    }

    // ---- Lending -------------------------------------------------------------------------------------------------

    [Fact]
    public void LoginOpenSession_OnOneSessionToken_LendsTheAnchor()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        using Pkcs11Session session = login.OpenSession();

        Assert.Single(_module.OpenSessions);
        AssertLent(session, AnchorId);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, session.GetSessionInfo().State);
        Assert.Equal(SessionAccess.ReadWrite, session.Access);
        Assert.Same(login, session.Login);
        Assert.Equal(CKR.CKR_SESSION_COUNT, _module.OpenSessionResults[^1]);
    }

    [Fact]
    public void LendingIsReactive_TokenInfoClaimsNoLimit()
    {
        _module.ReportSessionLimits = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        using Pkcs11Session session = login.OpenSession();

        Assert.Single(_module.OpenSessions);
        AssertLent(session, AnchorId);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, session.GetSessionInfo().State);
    }

    // Review Focus 5.
    [Fact]
    public void NoSessionLimit_NeverLends()
    {
        _module.MaxSessions = null;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        using Pkcs11Session session = login.OpenSession();

        Assert.Equal(2, _module.OpenSessions.Count);
        Assert.NotEqual(AnchorId, session.Core.SessionId);
        Assert.Null(Record.Loan);
    }

    [Fact]
    public void SecondOpenSession_WhileLent_ThrowsSessionCount_NamingTheLoan()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session first = login.OpenSession();

        var ex = Assert.Throws<Pkcs11SessionException>(() => login.OpenSession());

        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.Equal("C_OpenSession", ex.Method);
        Assert.Contains("lent", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Dispose that session first", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("dispose the login", ex.Message, StringComparison.OrdinalIgnoreCase);
        using (Pkcs11Key key = first.OpenKey(SigningKey))
            Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Ecdsa, "data"u8).Length);
        Assert.Single(_module.OpenSessions);
    }

    [Fact]
    public void DisposingLentSession_DoesNotCloseOrLogOut_AndCanBeLentAgain()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        ulong anchor = AnchorId;

        login.OpenSession().Dispose();

        Assert.Single(_module.OpenSessions);
        Assert.Equal(0, _module.LogoutCalls);
        Assert.True(login.IsActive);
        Assert.Null(Record.Loan);
        using Pkcs11Session again = login.OpenSession();
        AssertLent(again, anchor);
    }

    [Fact]
    public void LentSessionLastHolder_LogsOutThenClosesTheAnchor()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11Session session = login.OpenSession();

        login.Dispose();
        Assert.Equal(0, _module.LogoutCalls);
        session.Dispose();

        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
        Assert.False(Record.IsLoggedIn);
    }

    [Fact]
    public void ReadOnlyRequest_OnReadWriteAnchor_IsLent_AccessReadsReadWrite()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        using Pkcs11Session session = login.OpenSession(SessionAccess.ReadOnly);

        AssertLent(session, AnchorId);
        Assert.Equal(SessionAccess.ReadWrite, session.Access);
    }

    [Fact]
    public void ReadWriteRequest_OnReadOnlyAnchor_Refused_SaysReadOnly()
    {
        _module.MaxSessions = null;
        _module.MaxRwSessions = 1;
        using Pkcs11Session slotSession = Slot.OpenSession(SessionAccess.ReadWrite);
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Assert.False(Assert.IsType<Pkcs11SessionCore>(Record.Anchor).IsReadWrite);

        var ex = Assert.Throws<Pkcs11SessionException>(() => login.OpenSession());

        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.Equal("C_OpenSession", ex.Method);
        Assert.Contains("read-only", ex.Message, StringComparison.Ordinal);
        Assert.Contains("refused a read/write", ex.Message, StringComparison.Ordinal);
        Assert.Contains("SessionAccess.ReadOnly", ex.Message, StringComparison.Ordinal);
        Assert.IsAssignableFrom<Pkcs11SessionException>(ex.InnerException);
        Assert.Equal(CKR.CKR_SESSION_COUNT, ((Pkcs11Exception)ex.InnerException!).ReturnValue);
        Assert.Null(Record.Loan);
        using Pkcs11Session readOnly = login.OpenSession(SessionAccess.ReadOnly);
        Assert.NotEqual(AnchorId, readOnly.Core.SessionId);
        Assert.Equal(SessionAccess.ReadOnly, readOnly.Access);
    }

    [Fact]
    public void LentSession_HasItsOwnPolicyAndContextAuthentication()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        ContextAuthentication context = ContextAuthentication.FromPin(_ => new SecurePin(_module.ExpectedPin));
        login.ContextAuthentication = context;

        using Pkcs11Session session = login.OpenSession(policy: CryptoPolicy.NistApproved);

        AssertLent(session, AnchorId);
        Assert.Same(CryptoPolicy.NistApproved, session.Policy);
        Assert.Same(CryptoPolicy.Recommended, Assert.IsType<Pkcs11SessionCore>(Record.Anchor).Policy);
        Assert.Same(context, session.ContextAuthentication);
        Assert.Null(Record.Anchor!.ContextAuthentication);
    }

    // Review Focus 4: C_CloseSession parity.
    [Fact]
    public void LentSession_SessionObjects_DestroyedOnDispose_TokenObjectsKept()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using ObjectTemplate sessionTemplate = ObjectTemplate.ForData().Label("session").Build();
        using ObjectTemplate tokenTemplate = ObjectTemplate.ForData().Label("token").OnToken().Build();
        ulong sessionObject;
        ulong tokenObject;
        using (Pkcs11Session session = login.OpenSession())
        {
            AssertLent(session, AnchorId);
            using Pkcs11Object created = session.CreateObject(sessionTemplate);
            using Pkcs11Object kept = session.CreateObject(tokenTemplate);
            sessionObject = created.Handle.ObjectId;
            tokenObject = kept.Handle.ObjectId;
        }

        Assert.False(_module.HasObject(sessionObject));
        Assert.True(_module.HasObject(tokenObject));
        Assert.Single(_module.OpenSessions);
    }

    // Every function that creates an object through a lent session, with the handles it returns.
    public static TheoryData<string, bool> CreatingFunctions
    {
        get
        {
            var data = new TheoryData<string, bool>();
            foreach (string function in new[]
                { "C_GenerateKey", "C_GenerateKeyPair", "C_UnwrapKey", "C_DeriveKey", "C_EncapsulateKey", "C_DecapsulateKey" })
            {
                data.Add(function, false);
                data.Add(function, true);
            }
            return data;
        }
    }

    // Creates through core with function, CKA_TOKEN onToken; returns the handles made. The fake accepts any mechanism,
    // key and input, and the session's policy (AllowInsecure) any template: what is checked is the recording.
    private static List<ulong> CreateThrough(Pkcs11SessionCore core, string function, bool onToken, ulong key)
    {
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, onToken);
        using var label = new ObjectAttribute(CKA.CKA_LABEL, "made");
        List<ObjectAttribute> template = [token, label];
        var keyHandle = new ObjectHandle(key);
        switch (function)
        {
            case "C_GenerateKey":
                return [core.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template).ObjectId];
            case "C_GenerateKeyPair":
                core.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), template, template,
                    out ObjectHandle publicKey, out ObjectHandle privateKey);
                return [publicKey.ObjectId, privateKey.ObjectId];
            case "C_UnwrapKey":
                return [core.UnwrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP), keyHandle, new byte[24], template).ObjectId];
            case "C_DeriveKey":
                return [core.DeriveKey(new Mechanism(CKM.CKM_HKDF_DERIVE), keyHandle, template).ObjectId];
            case "C_EncapsulateKey":
                return [core.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), keyHandle, template,
                    LoginTokenModule.CiphertextLength).SharedKey.ObjectId];
            case "C_DecapsulateKey":
                return [core.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), keyHandle, new byte[LoginTokenModule.CiphertextLength],
                    template).ObjectId];
            default:
                throw new ArgumentOutOfRangeException(nameof(function), function, null);
        }
    }

    // Review Focus 4, for every creating function: a session object made through the lent session is destroyed on its
    // return, as C_CloseSession would; a token object is kept.
    [Theory]
    [MemberData(nameof(CreatingFunctions))]
    public void LentSession_ObjectsCreatedByKeyFunctions_SessionOnesDestroyedOnDispose_TokenOnesKept(string function, bool onToken)
    {
        ulong key = _module.AddObject(CKO.CKO_SECRET_KEY, "key", isPrivate: false, keyType: CKK.CKK_AES);
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        List<ulong> made;
        using (Pkcs11Session session = login.OpenSession(policy: CryptoPolicy.AllowInsecure))
        {
            AssertLent(session, AnchorId);
            made = CreateThrough(session.Core, function, onToken, key);
            Assert.All(made, h => Assert.True(_module.HasObject(h)));
        }

        Assert.NotEmpty(made);
        Assert.All(made, h => Assert.Equal(onToken, _module.HasObject(h)));
        Assert.True(_module.HasObject(key));
        Assert.Single(_module.OpenSessions);
    }

    // A module that encapsulates during the length probe (SoftHSM) makes a key there too: the return destroys both
    // session keys, the probe's and the real call's.
    [Fact]
    public void LentSession_EncapsulateLengthProbeKey_DestroyedOnDispose()
    {
        _module.EncapsulatesOnLengthProbe = true;
        ulong key = _module.AddObject(CKO.CKO_PUBLIC_KEY, "kem", isPrivate: false);
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        int before = _module.CreatedObjects.Count;
        ulong shared;
        using (Pkcs11Session session = login.OpenSession(policy: CryptoPolicy.AllowInsecure))
        {
            (byte[] ciphertext, ObjectHandle sharedKey) = session.Core.EncapsulateKey(
                new Mechanism(CKM.CKM_ML_KEM), new ObjectHandle(key), [token]);
            Assert.Equal(LoginTokenModule.CiphertextLength, ciphertext.Length);
            shared = sharedKey.ObjectId;
        }

        ulong[] made = [.. _module.CreatedObjects.Skip(before)];
        Assert.Equal(2, made.Length);
        Assert.Contains(shared, made);
        Assert.All(made, h => Assert.False(_module.HasObject(h)));
    }

    // A session object (CKA_TOKEN false) put on the token at handle, as another session of the application could
    // make one once the module gives a destroyed object's number to a new one.
    private void ReuseHandle(ulong handle, CKO objectClass, string label)
    {
        _module.NextObjectHandle = handle;
        Assert.Equal(handle, _module.AddObject(objectClass, label, isPrivate: false,
            more: new Dictionary<CKA, byte[]> { [CKA.CKA_TOKEN] = [0] }));
    }

    // Destroyed through the lent session, the object is forgotten: its number, given to a new session object exactly
    // like it (class, label, CKA_TOKEN false), is not destroyed on the return. Only ForgetDestroyed tells the two apart.
    [Fact]
    public void LentSession_DestroyedSessionObject_IsNotDestroyedAgain()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using ObjectTemplate sessionTemplate = ObjectTemplate.ForData().Label("session").Build();
        ulong handle;
        using (Pkcs11Session session = login.OpenSession())
        {
            Pkcs11Object created = session.CreateObject(sessionTemplate);
            handle = created.Handle.ObjectId;
            session.Core.DestroyObject(created.Handle);
            created.Dispose();
            ReuseHandle(handle, CKO.CKO_DATA, "session");
        }

        Assert.Single(_module.DestroyObjectCalls, h => h == handle);
        Assert.True(_module.HasObject(handle));
        Assert.Single(_module.OpenSessions);
        Assert.True(login.IsActive);
    }

    // Destroyed through another route (here the login's own core), the object stays recorded; its number, given to a
    // different session object (another class, or another label), is not destroyed on the return.
    [Theory]
    [InlineData(CKO.CKO_SECRET_KEY, "session")]
    [InlineData(CKO.CKO_DATA, "another")]
    public void LentSession_RecordedHandleReusedForAnotherSessionObject_IsNotDestroyed(CKO objectClass, string label)
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using ObjectTemplate sessionTemplate = ObjectTemplate.ForData().Label("session").Build();
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(Record.Anchor);
        ulong handle;
        using (Pkcs11Session session = login.OpenSession())
        {
            using Pkcs11Object created = session.CreateObject(sessionTemplate);
            handle = created.Handle.ObjectId;
            anchor.DestroyObject(created.Handle);
            ReuseHandle(handle, objectClass, label);
        }

        Assert.Single(_module.DestroyObjectCalls, h => h == handle);
        Assert.True(_module.HasObject(handle));
        Assert.Single(_module.OpenSessions);
    }

    [Fact]
    public void AbandonedOperation_WithoutSessionCancel_NextBorrowerGetsClearError()
    {
        _module.SupportsSessionCancel = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = ContextAuthentication.FromPin(_ => throw new InvalidOperationException("no PIN here"));
        using (Pkcs11Session session = login.OpenSession())
        using (Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc))
        {
            Assert.ThrowsAny<Exception>(() => key.Sign(Ecdsa, "data"u8));
            Assert.True(_module.HasActiveOperation(AnchorId));
        }
        login.ContextAuthentication = null;

        using Pkcs11Session next = login.OpenSession();
        using Pkcs11Key ordinary = next.OpenKey(SigningKey);
        var ex = Assert.Throws<Pkcs11UnclassifiedException>(() => ordinary.Sign(Ecdsa, "data"u8));

        AssertLent(next, AnchorId);
        Assert.Equal(CKR.CKR_OPERATION_ACTIVE, ex.ReturnValue);
        Assert.Contains("log in again", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("Open a new session", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AbandonedOperation_CancelledBySessionCancel_NextBorrowerSigns()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = ContextAuthentication.FromPin(_ => throw new InvalidOperationException("no PIN here"));
        using (Pkcs11Session session = login.OpenSession())
        using (Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc))
            Assert.ThrowsAny<Exception>(() => key.Sign(Ecdsa, "data"u8));
        Assert.Contains("C_SessionCancel", _module.CallLog);
        Assert.False(_module.HasActiveOperation(AnchorId));
        login.ContextAuthentication = null;

        using Pkcs11Session next = login.OpenSession();
        using Pkcs11Key ordinary = next.OpenKey(SigningKey);

        Assert.Equal(LoginTokenModule.SignatureLength, ordinary.Sign(Ecdsa, "data"u8).Length);
    }

    // ---- Concurrency on the lent anchor --------------------------------------------------------------------------

    // Review Focus 1. The share's C_Login holds the gate shared and waits for the anchor's lock, which the lent
    // session holds for its sign: it runs once the sign is over, never inside it.
    [Fact]
    public void ShareLogin_WhileLentSessionSigns_WaitsThenSucceeds()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(SigningKey);
        using var signing = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringSign = () => { signing.Set(); release.Wait(Bounded); };
        IReadOnlyList<string>? callsAtShareLogin = null;
        _module.DuringLogin = _ => callsAtShareLogin = _module.CallLog;
        _module.ClearCallLog();

        byte[]? signature = null;
        var (signer, signFailure) = Start(() => signature = key.Sign(Ecdsa, "data"u8));
        Assert.True(signing.Wait(Bounded, TestContext.Current.CancellationToken), "the sign never reached the module");
        Pkcs11Login? second = null;
        var (sharer, shareFailure) = Start(() => second = Slot.Login(TokenUser.User, _pin));
        try
        {
            Assert.False(SpinWait.SpinUntil(() => !sharer.IsAlive || _module.LoginCalls != 1, Watch),
                $"the share did not wait for the lent session's sign: {shareFailure()}");
        }
        finally
        {
            release.Set();
            Assert.True(signer.Join(Bounded), "the sign did not finish");
            Assert.True(sharer.Join(Bounded), "the share did not finish after the sign");
        }

        Assert.Null(signFailure());
        Assert.Null(shareFailure());
        Assert.Equal(LoginTokenModule.SignatureLength, signature!.Length);
        using Pkcs11Login shared = Assert.IsType<Pkcs11Login>(second);
        Assert.True(shared.IsActive);
        Assert.Contains("C_Sign", callsAtShareLogin!);
    }

    [Fact]
    public void LentSessionOperation_WhileShareLoginInFlight_WaitsNotThrows()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(SigningKey);
        key.Sign(Ecdsa, "warm"u8);
        using var inLogin = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringLogin = _ => { inLogin.Set(); release.Wait(Bounded); };

        var (sharer, shareFailure) = Start(() => Slot.Login(TokenUser.User, _pin).Dispose());
        Assert.True(inLogin.Wait(Bounded, TestContext.Current.CancellationToken), "the share's login never reached the module");
        byte[]? signature = null;
        var (signer, signFailure) = Start(() => signature = key.Sign(Ecdsa, "data"u8));
        try
        {
            Assert.False(SpinWait.SpinUntil(() => !signer.IsAlive, Watch),
                $"the lent session's sign did not wait for the share's login: {signFailure()}");
        }
        finally
        {
            release.Set();
            Assert.True(sharer.Join(Bounded), "the share did not finish");
            Assert.True(signer.Join(Bounded), "the sign did not finish after the share's login");
        }

        Assert.Null(shareFailure());
        Assert.Null(signFailure());
        Assert.Equal(LoginTokenModule.SignatureLength, signature!.Length);
    }

    [Fact]
    public void LentSession_TwoUserThreads_SecondThrowsConcurrentAccess()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var (holder, holdFailure) = Start(() =>
        {
            using (session.Core.AcquireExclusive())
            {
                held.Set();
                release.Wait(Bounded);
            }
        });
        Assert.True(held.Wait(Bounded, TestContext.Current.CancellationToken), "the lease was never taken");
        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() => session.GetSessionInfo());
            Assert.Contains("Concurrent access", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            release.Set();
            Assert.True(holder.Join(Bounded), "the holder did not finish");
        }

        Assert.Null(holdFailure());
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, session.GetSessionInfo().State);
    }

    // The anchor's core and its borrower share the mark of the application lease: one holding the lock is seen by the other.
    [Fact]
    public void LentSession_WhileAnchorLeasedByAnotherApplicationThread_ThrowsConcurrentAccess()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(Record.Anchor);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var (holder, _) = Start(() =>
        {
            using (anchor.AcquireExclusive())
            {
                held.Set();
                release.Wait(Bounded);
            }
        });
        Assert.True(held.Wait(Bounded, TestContext.Current.CancellationToken), "the anchor's lease was never taken");
        try
        {
            Assert.Throws<InvalidOperationException>(() => session.GetSessionInfo());
        }
        finally
        {
            release.Set();
            Assert.True(holder.Join(Bounded), "the holder did not finish");
        }
    }

    // The borrower shares the anchor's count of record sends: with a share's login queued on the lock, a second user
    // thread of the lent session waits (concurrent use is detected only best-effort then; see AcquireExclusive).
    [Fact]
    public void LentSession_WhileRecordSendQueued_SecondUserThreadWaits()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        Pkcs11SessionCore anchor = Assert.IsType<Pkcs11SessionCore>(Record.Anchor);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var (holder, _) = Start(() =>
        {
            using (session.Core.AcquireExclusive())
            {
                held.Set();
                release.Wait(Bounded);
            }
        });
        Assert.True(held.Wait(Bounded, TestContext.Current.CancellationToken), "the lease was never taken");
        var (sharer, shareFailure) = Start(() => Slot.Login(TokenUser.User, _pin).Dispose());
        Thread? second = null;
        Func<Exception?>? secondFailure = null;
        try
        {
            // The share's send is queued on the anchor's lock once the gate shows nothing else in its way and the
            // send has not reached the module.
            Assert.False(SpinWait.SpinUntil(() => !sharer.IsAlive || _module.LoginCalls != 1, Watch),
                $"the share did not wait for the lent session: {shareFailure()}");
            (second, secondFailure) = Start(() => session.GetSessionInfo());
            Assert.False(SpinWait.SpinUntil(() => !second.IsAlive, Watch),
                $"the second user thread did not wait behind the queued send: {secondFailure()}");
        }
        finally
        {
            release.Set();
            Assert.True(holder.Join(Bounded), "the holder did not finish");
            Assert.True(sharer.Join(Bounded), "the share did not finish");
            Assert.True(second is null || second.Join(Bounded), "the second user thread did not finish");
        }

        Assert.Null(shareFailure());
        Assert.Null(secondFailure?.Invoke());
        Assert.Same(anchor, Record.Anchor);
    }

    [Fact]
    public void ConcurrentOpenSession_OneLends_OtherGetsSessionCount()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using var barrier = new Barrier(2);
        var sessions = new Pkcs11Session?[2];
        var failures = new Exception?[2];
        var threads = Enumerable.Range(0, 2).Select(i => new Thread(() =>
        {
            barrier.SignalAndWait(Bounded);
            try { sessions[i] = login.OpenSession(); }
            catch (Exception ex) { failures[i] = ex; }
        })
        { IsBackground = true }).ToArray();
        foreach (Thread thread in threads)
            thread.Start();
        foreach (Thread thread in threads)
            Assert.True(thread.Join(Bounded), "an OpenSession did not finish");

        try
        {
            Pkcs11Session lent = Assert.Single(sessions, s => s is not null)!;
            var refused = Assert.IsType<Pkcs11SessionException>(Assert.Single(failures, f => f is not null));
            Assert.Equal(CKR.CKR_SESSION_COUNT, refused.ReturnValue);
            Assert.Contains("lent", refused.Message, StringComparison.Ordinal);
            AssertLent(lent, AnchorId);
            Assert.Single(_module.OpenSessions);
        }
        finally
        {
            foreach (Pkcs11Session? session in sessions)
                session?.Dispose();
        }
    }

    // ---- Races between building the borrower and recording the loan (TryLend's two phases) ------------------------

    [Fact]
    public void LoginEndsBetweenLendPhases_OpenSessionThrowsDisposed_NothingLent()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        TokenLoginRecord record = Record;
        record.BetweenLendPhases = () => record.MarkEnded(CKR.CKR_DEVICE_REMOVED);

        var ex = Assert.Throws<ObjectDisposedException>(() => login.OpenSession());

        Assert.Contains("login has ended", ex.Message, StringComparison.Ordinal);
        Assert.Null(record.Loan);
        Assert.False(login.IsActive);
        Assert.False(record.IsLoggedIn);
        Assert.Empty(_module.OpenSessions);
        Assert.Equal(0, _module.LogoutCalls);
    }

    [Fact]
    public void OwnerDisposingBetweenLendPhases_OpenSessionThrowsDisposed_NothingLent()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        TokenLoginRecord record = Record;
        ulong anchor = AnchorId;
        // The instant inside Pkcs11Library.Dispose between its flag being set and the library's holds being released.
        FieldInfo disposing = Assert.IsAssignableFrom<FieldInfo>(
            typeof(Pkcs11Library).GetField("_disposing", BindingFlags.NonPublic | BindingFlags.Instance));
        record.BetweenLendPhases = () => disposing.SetValue(_library, 1);

        var ex = Assert.Throws<ObjectDisposedException>(() => login.OpenSession());

        Assert.Equal(nameof(Pkcs11Library), ex.ObjectName);
        Assert.Null(record.Loan);
        Assert.True(login.IsActive);
        Assert.Equal(anchor, Assert.Single(_module.OpenSessions).Handle);
        Assert.Equal(0, _module.LogoutCalls);
    }

    [Fact]
    public void AnotherThreadLendsBetweenLendPhases_SecondRefusedNamingTheLoan_AnchorStaysOpen()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        TokenLoginRecord record = Record;
        ulong anchor = AnchorId;
        Pkcs11Session? other = null;
        Func<Exception?>? otherFailure = null;
        int lends = 0;
        record.BetweenLendPhases = () =>
        {
            if (Interlocked.Increment(ref lends) != 1)
                return; // the other thread's own lend
            var (thread, failure) = Start(() => other = login.OpenSession());
            otherFailure = failure;
            Assert.True(thread.Join(Bounded), "the other thread's OpenSession did not finish");
        };

        var ex = Assert.Throws<Pkcs11SessionException>(() => login.OpenSession());

        using Pkcs11Session lent = Assert.IsType<Pkcs11Session>(other);
        Assert.Null(otherFailure!());
        Assert.Equal(CKR.CKR_SESSION_COUNT, ex.ReturnValue);
        Assert.Contains("lent", ex.Message, StringComparison.Ordinal);
        Assert.Same(lent.Core, record.Loan?.Borrower);
        AssertLent(lent, anchor);
        Assert.Equal(CKS.CKS_RW_USER_FUNCTIONS, lent.GetSessionInfo().State);
        Assert.Equal(anchor, Assert.Single(_module.OpenSessions).Handle);
    }

    // ---- The SO, and token initialization ------------------------------------------------------------------------

    // Decision G: the SO's own session is read/write, the one R/W session the token allows; it is lent, and C_InitPIN
    // is still sent on it.
    [Fact]
    public void SoLogin_OneReadWriteSession_LendsAnchor_InitUserPinWorks()
    {
        _module.MaxSessions = null;
        _module.MaxRwSessions = 1;
        using Pkcs11Login so = Slot.Login(TokenUser.SecurityOfficer, _pin);
        ulong anchor = AnchorId;

        using Pkcs11Session session = so.OpenSession();
        using var userPin = new SecurePin("5678");
        so.InitUserPinWithPin(userPin);

        AssertLent(session, anchor);
        Assert.Equal(CKS.CKS_RW_SO_FUNCTIONS, session.GetSessionInfo().State);
        Assert.Equal(anchor, _module.LastInitPin?.Session);
        Assert.Equal("5678"u8.ToArray(), _module.LastInitPin?.Pin);
        Assert.Single(_module.OpenSessions);
    }

    [Fact]
    public void InitToken_WhileLent_RefusedSessionExists_AfterwardsSucceeds()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11Session session = login.OpenSession();

        var ex = Assert.Throws<Pkcs11SessionException>(() => Slot.InitTokenWithPin(_pin, "fresh"));
        Assert.Equal(CKR.CKR_SESSION_EXISTS, ex.ReturnValue);
        Assert.Equal(0, _module.InitTokenCalls);

        session.Dispose();
        login.Dispose();
        Slot.InitTokenWithPin(_pin, "fresh");

        Assert.Equal(1, _module.InitTokenCalls);
    }

    // ---- The login ending while lent -----------------------------------------------------------------------------

    [Fact]
    public void PinLockedOnLentSession_EndsLogin_ClosesAnchor_SessionRefusesThereafter()
    {
        _module.LockAfter = 1;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = ContextAuthentication.FromPin(_ => new SecurePin("9999"));
        Pkcs11Session session = login.OpenSession();
        using (Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc))
        {
            var locked = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(Ecdsa, "data"u8));
            Assert.Equal(CKR.CKR_PIN_LOCKED, locked.ReturnValue);
        }

        Assert.False(login.IsActive);
        Assert.Empty(_module.OpenSessions);
        Assert.Null(Record.Loan);
        var refused = Assert.Throws<ObjectDisposedException>(() => session.GetSessionInfo());
        Assert.Contains("lent", refused.Message, StringComparison.Ordinal);
        Assert.Contains("log in again", refused.Message, StringComparison.Ordinal);
        session.Dispose();
        Assert.Equal(0, _module.LogoutCalls);
    }

    // Review Focus 3: a loss seen through the borrower ends the login, as one seen on the anchor does.
    [Fact]
    public void AnchorLostThroughLentSession_EndsLogin_NewLoginSucceeds()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(SigningKey);
        key.Sign(Ecdsa, "warm"u8);
        _module.FailSession(AnchorId, CKR.CKR_DEVICE_REMOVED);

        Assert.Throws<Pkcs11TokenException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.False(login.IsActive);
        Assert.Empty(_module.OpenSessions);
        Assert.Throws<ObjectDisposedException>(() => session.GetSessionInfo());
        using Pkcs11Login again = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session next = again.OpenSession();
        AssertLent(next, AnchorId);
        Assert.Equal(0, _module.LogoutCalls);
    }

    [Fact]
    public void AnchorLostThroughShareSend_LentSessionRefusesThereafter()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        _module.FailSession(AnchorId, CKR.CKR_DEVICE_REMOVED);

        using Pkcs11Login again = Slot.Login(TokenUser.User, _pin);

        Assert.True(again.IsActive);
        Assert.False(login.IsActive);
        var refused = Assert.Throws<ObjectDisposedException>(() => session.GetSessionInfo());
        Assert.Contains("lent", refused.Message, StringComparison.Ordinal);
        Assert.Single(_module.OpenSessions);
        using Pkcs11Session next = again.OpenSession();
        AssertLent(next, AnchorId);
    }

    // ---- The library disposed while lent -------------------------------------------------------------------------

    // Review Focus 2: the library's disposal takes back its lent session before releasing its holds, so the final
    // logout runs on an anchor that is not lent.
    [Fact]
    public void LibraryDisposed_ReclaimsItsLentSession_ThenLogsOut()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11Session session = login.OpenSession();
        using ObjectTemplate sessionTemplate = ObjectTemplate.ForData().Label("session").Build();
        ulong sessionObject;
        using (Pkcs11Object created = session.CreateObject(sessionTemplate))
            sessionObject = created.Handle.ObjectId;

        _library.Dispose();

        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
        Assert.False(_module.HasObject(sessionObject));
        var refused = Assert.Throws<ObjectDisposedException>(() => session.GetSessionInfo());
        Assert.Equal(nameof(Pkcs11Session), refused.ObjectName);
        Assert.Contains("lent", refused.Message, StringComparison.Ordinal);
        Assert.Contains("library that lent it was disposed", refused.Message, StringComparison.Ordinal);
        session.Dispose();
        login.Dispose();
        Assert.Equal(1, _module.LogoutCalls);
    }

    [Fact]
    public void LibraryDisposed_WhileLentSessionSigns_WaitsForTheSign()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11Session session = login.OpenSession();
        Pkcs11Key key = session.OpenKey(SigningKey);
        using var signing = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        _module.DuringSign = () => { signing.Set(); release.Wait(Bounded); };

        byte[]? signature = null;
        var (signer, signFailure) = Start(() => signature = key.Sign(Ecdsa, "data"u8));
        Assert.True(signing.Wait(Bounded, TestContext.Current.CancellationToken), "the sign never reached the module");
        var (disposer, disposeFailure) = Start(_library.Dispose);
        try
        {
            Assert.False(SpinWait.SpinUntil(() => !disposer.IsAlive || _module.LogoutCalls != 0, Watch),
                $"the library's disposal did not wait for the lent session's sign: {disposeFailure()}");
        }
        finally
        {
            release.Set();
            Assert.True(signer.Join(Bounded), "the sign did not finish");
            Assert.True(disposer.Join(Bounded), "the library's disposal did not finish after the sign");
        }

        Assert.Null(signFailure());
        Assert.Null(disposeFailure());
        Assert.Equal(LoginTokenModule.SignatureLength, signature!.Length);
        Assert.Equal(1, _module.LogoutCalls);
        Assert.Empty(_module.OpenSessions);
        key.Dispose();
        session.Dispose();
        login.Dispose();
    }

    [Fact]
    public void OtherLibraryDisposed_LoanStays()
    {
        using Pkcs11Library other = _module.Load();
        Pkcs11Slot otherSlot = Assert.Single(other.GetSlotList());
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Login otherLogin = otherSlot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = otherLogin.OpenSession();
        TokenLoginRecord record = Record;
        AssertLent(session, AnchorId);

        _library.Dispose();

        Assert.True(otherLogin.IsActive);
        Assert.Same(session.Core, record.Loan?.Borrower);
        using (Pkcs11Key key = session.OpenKey(SigningKey))
            Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Ecdsa, "data"u8).Length);
        Assert.Equal(0, _module.LogoutCalls);
        login.Dispose();
    }
}
