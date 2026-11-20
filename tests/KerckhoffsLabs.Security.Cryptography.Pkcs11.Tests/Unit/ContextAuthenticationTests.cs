using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// PKCS#11 v3.2 private_key_objects.md: a private key with <c>CKA_ALWAYS_AUTHENTICATE</c> true needs
/// <c>C_Login(CKU_CONTEXT_SPECIFIC)</c> "immediately after a cryptographic operation using the key has been
/// initiated" for each use (sign or decrypt). The library sends it on the operation's own session, between the
/// <c>C_*Init</c> and the operation, with the PIN from the session's <see cref="ContextAuthentication"/>.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ContextAuthenticationTests : IDisposable
{
    private const string AlwaysAuthenticateEc = "aa-ec";
    private const string AlwaysAuthenticateRsa = "aa-rsa";
    private const string OrdinaryEc = "plain-ec";
    private const string AlwaysAuthenticateDsa = "aa-dsa";
    private const string AlwaysAuthenticateMlDsa = "aa-ml-dsa";
    private const string AlwaysAuthenticateSlhDsa = "aa-slh-dsa";

    private static readonly Mechanism Ecdsa = new(CKM.CKM_ECDSA_SHA256);

    private readonly CapturingLogger _logger = new();
    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public ContextAuthenticationTests()
    {
        var alwaysAuthenticate = new Dictionary<CKA, byte[]> { [CKA.CKA_ALWAYS_AUTHENTICATE] = [1] };
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateEc, isPrivate: true, keyType: CKK.CKK_EC, more: alwaysAuthenticate);
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateRsa, isPrivate: true, keyType: CKK.CKK_RSA,
            more: new Dictionary<CKA, byte[]>(alwaysAuthenticate) { [CKA.CKA_MODULUS_BITS] = LoginTokenModule.Ulong(2048) });
        _module.AddObject(CKO.CKO_PRIVATE_KEY, OrdinaryEc, isPrivate: true, keyType: CKK.CKK_EC);
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateDsa, isPrivate: true, keyType: CKK.CKK_DSA, more: alwaysAuthenticate);
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateMlDsa, isPrivate: true, keyType: CKK.CKK_ML_DSA,
            more: new Dictionary<CKA, byte[]>(alwaysAuthenticate) { [CKA.CKA_PARAMETER_SET] = LoginTokenModule.Ulong((ulong)CkpMlDsa.CKP_ML_DSA_44) });
        _module.AddObject(CKO.CKO_PRIVATE_KEY, AlwaysAuthenticateSlhDsa, isPrivate: true, keyType: CKK.CKK_SLH_DSA,
            more: new Dictionary<CKA, byte[]>(alwaysAuthenticate) { [CKA.CKA_PARAMETER_SET] = LoginTokenModule.Ulong((ulong)CkpSlhDsa.CKP_SLH_DSA_SHA2_128S) });
        _library = _module.Load(new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(_logger) });
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    private ContextAuthentication RightPin() => ContextAuthentication.FromPinSource(_ => new SecurePin(_module.ExpectedPin));

    private static ContextAuthentication WrongPin() => ContextAuthentication.FromPinSource(_ => new SecurePin("9999"));

    private static Mechanism Oaep() => new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));

    // The calls after the one that opened the operation, up to the first context login, and the rest.
    private static void AssertContextLoginBetween(IReadOnlyList<string> log, string init, string operation)
    {
        Assert.Equal([init, LoginTokenModule.ContextLogin], log.Take(2));
        Assert.Single(log, LoginTokenModule.ContextLogin);
        Assert.NotEmpty(log.Skip(2));
        Assert.All(log.Skip(2), call => Assert.Equal(operation, call));
    }

    [Fact]
    public void Sign_AlwaysAuthenticateKey_SendsContextLoginBetweenInitAndSign()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = RightPin();
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        Assert.True(key.AlwaysAuthenticate);
        _module.ClearCallLog();

        byte[] signature = key.Sign(Ecdsa, "data"u8);

        Assert.Equal(LoginTokenModule.SignatureLength, signature.Length);
        AssertContextLoginBetween(_module.CallLog, "C_SignInit", "C_Sign");
        Assert.Equal([_module.ExpectedPin], _module.ContextPins);
        // A context login is not a token login: the token login is untouched.
        Assert.True(login.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    [Fact]
    public void Sign_EachOperation_AuthenticatesAgain()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = RightPin();
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        key.Sign(Ecdsa, "one"u8);
        key.Sign(Ecdsa, "two"u8);

        Assert.Equal(2, _module.CallLog.Count(c => c == LoginTokenModule.ContextLogin));
    }

    [Fact]
    public void Decrypt_AlwaysAuthenticateKey_SendsContextLoginBetweenInitAndDecrypt()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = RightPin();
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateRsa);
        _module.ClearCallLog();

        byte[] ciphertext = new byte[256];
        ciphertext[^1] = 7;
        byte[] plaintext = key.Decrypt(Oaep(), ciphertext);

        Assert.Equal(ciphertext, plaintext);
        AssertContextLoginBetween(_module.CallLog, "C_DecryptInit", "C_Decrypt");
    }

    // A PIN the token refused is not sent again: each wrong context PIN costs one of the user PIN's retries, and
    // repeating it on every operation would lock the PIN application-wide. A new source bringing the same PIN is refused
    // too; a different PIN is sent.
    [Fact]
    public void WrongContextPin_IsNotResent_ADifferentPinIs()
    {
        _module.LockAfter = 5;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = WrongPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var first = Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
        Assert.Equal(CKR.CKR_PIN_INCORRECT, first.ReturnValue);
        var second = Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
        Assert.Equal(CKR.CKR_PIN_INCORRECT, second.ReturnValue);
        Assert.Contains("refused this PIN before", second.Message, StringComparison.Ordinal);
        Assert.Single(_module.CallLog, LoginTokenModule.ContextLogin); // one retry used, not two
        Assert.True(login.IsActive);

        session.ContextAuthentication = WrongPin();
        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
        Assert.Single(_module.CallLog, LoginTokenModule.ContextLogin);
        Assert.DoesNotContain("C_SignInit", _module.CallLog.Skip(_module.CallLog.ToList().IndexOf(LoginTokenModule.ContextLogin) + 1));

        session.ContextAuthentication = RightPin();
        Assert.NotEmpty(key.Sign(Ecdsa, "data"u8));
    }

    // The per-request pattern assigns the same source to a new login or session each time. Assigning a refused
    // source again must not re-arm it, or each request would spend one of the user PIN's retries until it locks.
    [Fact]
    public void WrongContextPin_AssignedAgainPerRequest_NotResent()
    {
        _module.LockAfter = 5;
        ContextAuthentication wrong = WrongPin();
        using Pkcs11Login holder = Slot.Login(TokenUser.User, _pin);
        _module.ClearCallLog();

        for (int request = 0; request < 3; request++)
        {
            using Pkcs11Login login = holder.Share();
            login.ContextAuthentication = wrong;
            using Pkcs11Session session = login.OpenSession();
            session.ContextAuthentication = wrong;
            using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
            Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
        }

        Assert.Single(_module.CallLog, LoginTokenModule.ContextLogin); // one retry in all
        Assert.True(holder.IsActive);
    }

    // The refusal belongs to the token and the key, not to a session: another session (here, both opened from the
    // login) does not send the refused PIN again either.
    [Fact]
    public void WrongContextPin_FromTheLogin_NotResentOnAnotherSession()
    {
        _module.LockAfter = 5;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = WrongPin();
        using Pkcs11Session first = login.OpenSession();
        using Pkcs11Session second = login.OpenSession();
        using Pkcs11Key firstKey = first.OpenKey(AlwaysAuthenticateEc);
        using Pkcs11Key secondKey = second.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        Assert.Throws<Pkcs11AuthenticationException>(() => firstKey.Sign(Ecdsa, "data"u8));
        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => secondKey.Sign(Ecdsa, "data"u8));

        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
        Assert.Single(_module.CallLog, LoginTokenModule.ContextLogin);
    }

    // A source made afresh for each request (a scoped DI registration, a FromPin in the handler) brings the same stale
    // PIN each time: it is sent once, not once per request, so the user PIN does not lock.
    [Fact]
    public void WrongContextPin_NewSourcePerRequest_SentOnce()
    {
        _module.LockAfter = 3;
        using Pkcs11Login holder = Slot.Login(TokenUser.User, _pin);
        _module.ClearCallLog();

        for (int request = 0; request < 5; request++)
        {
            using Pkcs11Login login = holder.Share();
            login.ContextAuthentication = WrongPin();
            using Pkcs11Session session = login.OpenSession();
            using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
            var ex = Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
            Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        }

        Assert.Single(_module.CallLog, LoginTokenModule.ContextLogin);
        Assert.True(holder.IsActive);
    }

    // The refusal is the token's context logins', not one key's: on most tokens the context PIN is the user's, so
    // with several always-authenticate keys a stale PIN still costs one retry, not one per key.
    [Fact]
    public void WrongContextPin_RefusedForOneKey_NotSentForAnother()
    {
        _module.LockAfter = 5;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = WrongPin();
        using Pkcs11Key ec = session.OpenKey(AlwaysAuthenticateEc);
        using Pkcs11Key rsa = session.OpenKey(AlwaysAuthenticateRsa);
        _module.ClearCallLog();

        Assert.Throws<Pkcs11AuthenticationException>(() => ec.Sign(Ecdsa, "data"u8));
        Assert.Throws<Pkcs11AuthenticationException>(() => rsa.Decrypt(Oaep(), new byte[256]));

        Assert.Single(_module.CallLog, LoginTokenModule.ContextLogin);
    }

    // A user login that succeeds proves the user PIN, not a context PIN refused before (a key's own PIN, or a stale one):
    // that refusal stands, so a stale context PIN is not sent again once per request, each request logging in afresh.
    [Fact]
    public void UserLoginSucceeds_ContextRefusalStands()
    {
        _module.LockAfter = 5;
        using (Pkcs11Login login = Slot.Login(TokenUser.User, _pin))
        using (Pkcs11Session session = login.OpenSession())
        {
            session.ContextAuthentication = WrongPin();
            using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
            Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
        }
        Assert.Equal(1, Slot.LoginRecord.RefusedPins.Count);

        using Pkcs11Login again = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session next = again.OpenSession();
        next.ContextAuthentication = WrongPin();
        using Pkcs11Key nextKey = next.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var refused = Assert.Throws<Pkcs11AuthenticationException>(() => nextKey.Sign(Ecdsa, "data"u8));

        Assert.Contains("refused this PIN before", refused.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
        Assert.Equal(1, Slot.LoginRecord.RefusedPins.Count);
    }

    // A null mechanism is the caller's mistake: refused before the PIN callback, which never runs for it.
    [Fact]
    public void NullMechanism_RefusedBeforeThePinCallback()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        int asked = 0;
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ =>
        {
            asked++;
            return new SecurePin(_module.ExpectedPin);
        });
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);

        Assert.Throws<ArgumentNullException>(() => key.Sign(null!, "data"u8));

        Assert.Equal(0, asked);
    }

    // Pkcs11Slot.ForgetRefusedPins lets a refused PIN be sent again: for a PIN changed back outside the library.
    [Fact]
    public void ForgetRefusedPins_RefusedContextPin_SentAgain()
    {
        _module.LockAfter = 5;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = WrongPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));
        _module.ClearCallLog();

        Slot.ForgetRefusedPins();
        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Single(_module.CallLog, LoginTokenModule.ContextLogin);
    }

    // PKCS#11 v3.2 C_Login: a key that needs no re-authentication for this operation, though it reports
    // CKA_ALWAYS_AUTHENTICATE, has the context login answered CKR_OPERATION_NOT_INITIALIZED, "but the active
    // cryptographic operation will not be affected": the sign goes on.
    [Fact]
    public void ContextLogin_OperationNotInitialized_KeyNeedsNone_SignGoesOn()
    {
        _module.EnforcesAlwaysAuthenticate = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = RightPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        byte[] signature = key.Sign(Ecdsa, "data"u8);

        Assert.Equal(LoginTokenModule.SignatureLength, signature.Length);
        Assert.Equal(["C_SignInit", LoginTokenModule.ContextLogin, "C_Sign"], _module.CallLog.Take(3));
    }

    // Without C_SessionCancel, a context login that failed for another reason than the PIN (the module may not
    // enforce the context login at all) is not finished with a C_Sign: such a module would sign, and spend a one-time
    // leaf of a stateful key. The operation stays abandoned, and the next sign says why.
    [Fact]
    public void NoSessionCancel_ContextLoginFailsOtherThanPin_NoSignSent_OperationAbandoned()
    {
        _module.SupportsSessionCancel = false;
        _module.EnforcesAlwaysAuthenticate = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = RightPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        int signatures = 0;
        _module.DuringSign = () => signatures++;
        _module.ClearCallLog();
        _module.FailNext("C_Login", CKR.CKR_USER_TYPE_INVALID);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(CKR.CKR_USER_TYPE_INVALID, ex.ReturnValue);
        Assert.Equal(0, signatures);
        Assert.DoesNotContain("C_Sign", _module.CallLog);
        Assert.True(_module.HasActiveOperation(session.Core.SessionId));
        var next = Assert.Throws<Pkcs11UnclassifiedException>(() => key.Sign(Ecdsa, "data"u8));
        Assert.Equal(CKR.CKR_OPERATION_ACTIVE, next.ReturnValue);
    }

    // Without C_SessionCancel, a refused context PIN on a module that answers the length query with a length (it does
    // not enforce the context login): the full call is never sent, so nothing is signed; the session is closed to end
    // the operation, and says so on its next call.
    [Fact]
    public void NoSessionCancel_PinRefused_LengthAnswered_NothingSigned_SessionClosed()
    {
        _module.SupportsSessionCancel = false;
        _module.EnforcesAlwaysAuthenticate = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = RightPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        ulong sessionId = session.Core.SessionId;
        int signatures = 0;
        _module.DuringSign = () => signatures++;
        _module.FailNext("C_Login", CKR.CKR_PIN_INCORRECT);

        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(0, signatures);
        Assert.False(_module.HasActiveOperation(sessionId));
        Assert.DoesNotContain(_module.OpenSessions, open => open.Handle == sessionId);
        Assert.Contains(_logger.Entries, entry => entry.EventId.Name == "SessionClosedToEndOperation");
        var closed = Assert.Throws<Pkcs11SessionException>(() => key.Sign(Ecdsa, "data"u8));
        Assert.Contains("closed to end an operation", closed.Message, StringComparison.Ordinal);
        Assert.True(login.IsActive);
    }

    // ends the unauthenticated operation (CKR_USER_NOT_LOGGED_IN), without a signature, and the next sign works.
    [Fact]
    public void NoSessionCancel_PinRefused_LengthQueryEndsTheOperation_NextSignWorks()
    {
        _module.SupportsSessionCancel = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = WrongPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        int signatures = 0;
        _module.DuringSign = () => signatures++;

        Assert.Throws<Pkcs11AuthenticationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(0, signatures);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));
        session.ContextAuthentication = RightPin();
        Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Ecdsa, "data"u8).Length);
    }

    // The PIN callback runs before the operation takes its session: it is not counted on the token's operation gate,
    // so a logout never waits for it, and a thread it waits for may log in or out without waiting for it in turn.
    [Fact]
    public void PinCallback_RunsBeforeTheOperation_NotCountedOnTheGate()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        int countedDuringCallback = -1;
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ =>
        {
            countedDuringCallback = Slot.LoginRecord.ActiveOperations;
            return new SecurePin(_module.ExpectedPin);
        });
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        Assert.NotEmpty(key.Sign(Ecdsa, "data"u8));

        Assert.Equal(0, countedDuringCallback);
    }

    // A callback that returns a SecurePin it keeps: the library disposed it after the first use, so the second
    // operation is refused before C_SignInit, rather than failing after it.
    [Fact]
    public void PinCallback_ReturnsAKeptPin_SecondUseRefusedBeforeInit()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        var kept = new SecurePin(_module.ExpectedPin);
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ => kept);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        Assert.NotEmpty(key.Sign(Ecdsa, "data"u8));
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Contains("disposed SecurePin", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("C_SignInit", _module.CallLog);
    }

    // A pinpad context login on a token without a protected authentication path is refused before the module.
    [Fact]
    public void Pinpad_TokenWithoutProtectedPath_Refused_NoContextLogin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.Pinpad;
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Contains("protected authentication path", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("C_SignInit", _module.CallLog);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
    }

    [Fact]
    public void Sign_OrdinaryKey_NoContextLogin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = ContextAuthentication.FromPinSource(_ => throw new InvalidOperationException("not to be asked"));
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(OrdinaryEc);
        _module.ClearCallLog();

        key.Sign(Ecdsa, "data"u8);

        Assert.False(key.AlwaysAuthenticate);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
        Assert.Equal("C_SignInit", _module.CallLog[0]);
    }

    [Fact]
    public void AlwaysAuthenticate_ReadOnceAndCached()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(OrdinaryEc);

        // The first use reads the attribute (with whatever else a first use looks up); later ones read nothing more.
        key.Sign(Ecdsa, "one"u8);
        int afterFirstUse = _module.CallCount("C_GetAttributeValue");
        Assert.False(key.AlwaysAuthenticate);
        key.Sign(Ecdsa, "two"u8);
        key.Sign(Ecdsa, "three"u8);
        Assert.False(key.AlwaysAuthenticate);

        Assert.Equal(afterFirstUse, _module.CallCount("C_GetAttributeValue"));
    }

    [Fact]
    public void NoSource_RefusedBeforeInit()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        // A slot session sees the login but has no source of its own.
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        Assert.Null(session.ContextAuthentication);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Contains(nameof(ContextAuthentication), ex.Message);
        Assert.DoesNotContain("C_SignInit", _module.CallLog);
        Assert.Empty(_module.CallLog);
    }

    [Fact]
    public void NoSource_OnLogin_SessionRefusesBeforeInit()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateRsa);
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Decrypt(Oaep(), new byte[256]));

        Assert.Contains(nameof(ContextAuthentication), ex.Message);
        Assert.Empty(_module.CallLog);
    }

    [Fact]
    public void WrongPin_OperationAbandoned_ErrorPropagates()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = WrongPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(CKR.CKR_PIN_INCORRECT, ex.ReturnValue);
        // The operation the wrong PIN left active is cancelled, and nothing is signed.
        Assert.Equal(["C_SignInit", LoginTokenModule.ContextLogin, "C_SessionCancel"], _module.CallLog);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));
        // A wrong PIN is not the end of the token login.
        Assert.True(login.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);

        session.ContextAuthentication = RightPin();
        Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Ecdsa, "data"u8).Length);
    }

    [Fact]
    public void PinLocked_EndsTheLogin()
    {
        _module.LockAfter = 1;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = WrongPin();
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        int logouts = _module.LogoutCalls;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(CKR.CKR_PIN_LOCKED, ex.ReturnValue);
        Assert.False(login.IsActive);
        Assert.False(session.LoginInfo!.IsActive);
        Assert.Null(_module.LoggedIn);

        // The module ended the login: releasing the holders sends no C_Logout.
        session.Dispose();
        login.Dispose();
        Assert.Equal(logouts, _module.LogoutCalls);
    }

    [Fact]
    public async Task SourceThrows_LockAndGateReleased_NextOperationWorks()
    {
        var boom = new InvalidOperationException("secret store unavailable");
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ => throw boom);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Same(boom, ex);
        // The PIN is asked for before C_SignInit: a callback that fails starts nothing.
        Assert.Empty(_module.CallLog);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));

        // The operation's count on the gate was given back: no operation is left in flight on the token.
        Assert.Equal(0, session.Core.LoginRecord.ActiveOperations);

        // The session lock is released: another thread can use the session.
        session.ContextAuthentication = RightPin();
        byte[] signature = await Task.Run(() => key.Sign(Ecdsa, "data"u8), TestContext.Current.CancellationToken);
        Assert.Equal(LoginTokenModule.SignatureLength, signature.Length);
    }

    // On a module without C_SessionCancel (before v3.0), a callback that fails must not leave an operation for the
    // library to finish with a real C_Sign: a module that does not enforce CKA_ALWAYS_AUTHENTICATE would sign.
    [Fact]
    public void SourceThrows_NoSessionCancel_NothingSigned_NextOperationWorks()
    {
        _module.SupportsSessionCancel = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ => throw new InvalidOperationException("no pin"));
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.DoesNotContain("C_SignInit", _module.CallLog);
        Assert.DoesNotContain("C_Sign", _module.CallLog);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));

        session.ContextAuthentication = RightPin();
        Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Ecdsa, "data"u8).Length);
    }

    [Fact]
    public void SourceReturnsNull_Refused()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ => null!);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Contains(nameof(ContextAuthentication), ex.Message);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));
    }

    // The callback releases the last holder: it runs before the sign takes its session, so the logout is sent at once,
    // and the sign then finds its private key's login ended. Nothing reaches the module.
    [Fact]
    public void SourceDisposesTheLogin_LoggedOutAtOnce_SignRefused()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        session.ContextAuthentication = ContextAuthentication.FromPinSource(_ =>
        {
            login.Dispose();
            return new SecurePin(_module.ExpectedPin);
        });
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);

        _module.ClearCallLog();

        Assert.Throws<Pkcs11LoginEndedException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(1, _module.LogoutCalls);
        Assert.DoesNotContain("C_SignInit", _module.CallLog);
        Assert.False(login.IsActive);
        Assert.Null(_module.LoggedIn);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));
    }

    [Fact]
    public void PinDisposedAfterUse()
    {
        SecurePin? handedOut = null;
        Pkcs11Key? askedFor = null;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPinSource(k =>
        {
            askedFor = k;
            return handedOut = new SecurePin(_module.ExpectedPin);
        });
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);

        key.Sign(Ecdsa, "data"u8);

        Assert.Same(key, askedFor);
        Assert.NotNull(handedOut);
        Assert.Throws<ObjectDisposedException>(() => handedOut.Length);
    }

    [Fact]
    public void Pinpad_SendsNullPin()
    {
        _module.ProtectedAuthenticationPath = true;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.Pinpad;
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        key.Sign(Ecdsa, "data"u8);

        AssertContextLoginBetween(_module.CallLog, "C_SignInit", "C_Sign");
        byte[] sent = Assert.Single(_module.ContextPins);
        Assert.Empty(sent);
    }

    // Without C_SessionCancel, a context login the user cancelled on the pinpad, or answered with an expired PIN: the
    // operation is ended without being finished, so a retry is not refused for good with CKR_OPERATION_ACTIVE.
    [Theory]
    [InlineData(CKR.CKR_FUNCTION_CANCELED)]
    [InlineData(CKR.CKR_PIN_EXPIRED)]
    public void NoSessionCancel_ContextLoginCancelledOrPinExpired_OperationEnded(CKR answer)
    {
        _module.SupportsSessionCancel = false;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = RightPin();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        ulong sessionId = session.Core.SessionId;
        int signatures = 0;
        _module.DuringSign = () => signatures++;
        _module.FailNext("C_Login", answer);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(answer, ex.ReturnValue);
        Assert.Equal(0, signatures);
        Assert.False(_module.HasActiveOperation(sessionId));
        Assert.True(login.IsActive);
        using Pkcs11Session retry = login.OpenSession();
        retry.ContextAuthentication = RightPin();
        using Pkcs11Key again = retry.OpenKey(AlwaysAuthenticateEc);
        Assert.NotEmpty(again.Sign(Ecdsa, "data"u8));
    }

    // Each BCL-shaped adapter turns a context login that cannot be made into a CryptographicException, in every signing
    // or decrypting method.
    [Fact]
    public void Adapters_NoSource_EveryMethodThrowsCryptographicException()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        using Pkcs11Key rsaKey = session.OpenKey(AlwaysAuthenticateRsa);
        using Pkcs11Key ecKey = session.OpenKey(AlwaysAuthenticateEc);
        using RSA rsa = new RSAPkcs11(rsaKey);
        using ECDsa ecdsa = new ECDsaPkcs11(ecKey);
        byte[] hash = SHA256.HashData([1, 2, 3]);
        byte[] destination = new byte[512];

        AssertWrapped(() => rsa.TrySignData([1, 2, 3], destination, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, out _));
        AssertWrapped(() => rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        AssertWrapped(() => rsa.Decrypt(new byte[256], RSAEncryptionPadding.OaepSHA256));
        AssertWrapped(() => ecdsa.SignHash(hash));
        using Pkcs11Key dsaKey = session.OpenKey(AlwaysAuthenticateDsa);
#pragma warning disable KLPKCS11006 // DSA, for interop with existing keys: its adapter wraps the refusal too
        using DSA dsa = new DSAPkcs11(dsaKey);
#pragma warning restore KLPKCS11006
        AssertWrapped(() => dsa.CreateSignature(new byte[20]));
        using Pkcs11Key mlDsaKey = session.OpenKey(AlwaysAuthenticateMlDsa);
        using MLDsa mlDsa = new MLDsaPkcs11(mlDsaKey);
        AssertWrapped(() => mlDsa.SignData([1, 2, 3]));
        using Pkcs11Key slhDsaKey = session.OpenKey(AlwaysAuthenticateSlhDsa);
#pragma warning disable SYSLIB5006 // SLH-DSA is experimental in .NET
        using SlhDsa slhDsa = new SlhDsaPkcs11(slhDsaKey);
        AssertWrapped(() => slhDsa.SignData([1, 2, 3]));
#pragma warning restore SYSLIB5006

        static void AssertWrapped(Action call)
        {
            var ex = Assert.Throws<CryptographicException>(call);
            Assert.IsType<InvalidOperationException>(ex.InnerException);
        }
    }

    // Code written against RSA catches CryptographicException: a context login that cannot be made (here, no source)
    // reaches it as one, with the library's own InvalidOperationException inside; the key's own methods keep theirs.
    [Fact]
    public void Adapter_NoSource_ThrowsCryptographicException()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateRsa);
        using RSA rsa = new RSAPkcs11(key);

        var ex = Assert.Throws<CryptographicException>(
            () => rsa.SignData([1, 2, 3], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        Assert.IsType<InvalidOperationException>(ex.InnerException);
        using Pkcs11Key ec = session.OpenKey(AlwaysAuthenticateEc);
        Assert.Throws<InvalidOperationException>(() => ec.Sign(Ecdsa, "data"u8));
    }

    // A PIN the caller keeps: used for every operation and never disposed by the library.
    [Fact]
    public void FromPin_APinTheCallerKeeps_UsedForEachOperation_NotDisposed()
    {
        using var kept = new SecurePin(_module.ExpectedPin);
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        session.ContextAuthentication = ContextAuthentication.FromPin(kept);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateRsa);
        using RSA rsa = new RSAPkcs11(key);

        Assert.NotEmpty(rsa.SignData([1, 2, 3], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        Assert.NotEmpty(rsa.SignData([4, 5, 6], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        Assert.False(kept.IsDisposed);
        Assert.Equal(2, _module.ContextPins.Count);
        kept.Dispose();
        Assert.Throws<ObjectDisposedException>(
            () => rsa.SignData([7], HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Fact]
    public void Adapter_RSAPkcs11_SignData_UsesSessionSource()
    {
        Pkcs11Key? askedFor = null;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadOnly);
        session.ContextAuthentication = ContextAuthentication.FromPinSource(k =>
        {
            askedFor = k;
            return new SecurePin(_module.ExpectedPin);
        });
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateRsa);
        using RSA rsa = new RSAPkcs11(key);
        _module.ClearCallLog();

        byte[] signature = rsa.SignData([1, 2, 3], HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.NotEmpty(signature);
        Assert.Same(key, askedFor);
        AssertContextLoginBetween(_module.CallLog, "C_SignInit", "C_Sign");
    }

    [Fact]
    public void Session_CopiesLoginSourceAtOpen()
    {
        ContextAuthentication first = RightPin();
        ContextAuthentication second = ContextAuthentication.Pinpad;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = first;

        using Pkcs11Session fromLogin = login.OpenSession();
        login.ContextAuthentication = second;
        using Pkcs11Session later = login.OpenSession();
        using Pkcs11Session fromSlot = Slot.OpenSession(SessionAccess.ReadOnly);

        Assert.Same(first, fromLogin.ContextAuthentication);
        Assert.Same(second, later.ContextAuthentication);
        Assert.Null(fromSlot.ContextAuthentication);

        fromLogin.ContextAuthentication = null;
        Assert.Null(fromLogin.ContextAuthentication);
        Assert.Same(second, login.ContextAuthentication);
    }

    [Fact]
    public void FromPin_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ContextAuthentication.FromPinSource((Func<Pkcs11Key, SecurePin>)null!));
        Assert.Throws<ArgumentNullException>(() => ContextAuthentication.FromPin((SecurePin)null!));
        Assert.Same(ContextAuthentication.Pinpad, ContextAuthentication.Pinpad);
    }
}
