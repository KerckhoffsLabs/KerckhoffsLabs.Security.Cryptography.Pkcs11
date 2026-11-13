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

    private static readonly Mechanism Ecdsa = new(CKM.CKM_ECDSA_SHA256);

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

    private ContextAuthentication RightPin() => ContextAuthentication.FromPin(_ => new SecurePin(_module.ExpectedPin));

    private static ContextAuthentication WrongPin() => ContextAuthentication.FromPin(_ => new SecurePin("9999"));

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

    [Fact]
    public void Sign_OrdinaryKey_NoContextLogin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = ContextAuthentication.FromPin(_ => throw new InvalidOperationException("not to be asked"));
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
        using Pkcs11Session session = Slot.OpenSession();
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
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        login.ContextAuthentication = WrongPin();
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        int logouts = _module.LogoutCalls;

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Equal(CKR.CKR_PIN_LOCKED, ex.ReturnValue);
        Assert.False(login.IsActive);
        Assert.False(session.Login!.IsActive);
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
        session.ContextAuthentication = ContextAuthentication.FromPin(_ => throw boom);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Same(boom, ex);
        Assert.Equal(["C_SignInit", "C_SessionCancel"], _module.CallLog);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));

        // The gate is no longer held on this thread: a release here is not refused as one inside an operation.
        Slot.Login(TokenUser.User, _pin).Dispose();

        // The session lock is released: another thread can use the session.
        session.ContextAuthentication = RightPin();
        byte[] signature = await Task.Run(() => key.Sign(Ecdsa, "data"u8), TestContext.Current.CancellationToken);
        Assert.Equal(LoginTokenModule.SignatureLength, signature.Length);
    }

    [Fact]
    public void SourceReturnsNull_Refused()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPin(_ => null!);
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);
        _module.ClearCallLog();

        var ex = Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        Assert.Contains(nameof(ContextAuthentication), ex.Message);
        Assert.DoesNotContain(LoginTokenModule.ContextLogin, _module.CallLog);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));
    }

    [Fact]
    public void SourceDisposesTheLogin_ReleaseRefused_StateConsistent()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPin(_ =>
        {
            login.Dispose();
            return new SecurePin(_module.ExpectedPin);
        });
        using Pkcs11Key key = session.OpenKey(AlwaysAuthenticateEc);

        Assert.Throws<InvalidOperationException>(() => key.Sign(Ecdsa, "data"u8));

        // The release was refused before anything changed: the login is still held and still logged in.
        Assert.True(login.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
        Assert.False(_module.HasActiveOperation(session.Core.SessionId));

        session.ContextAuthentication = RightPin();
        key.Sign(Ecdsa, "data"u8);
        login.Dispose();
        Assert.False(login.IsActive);
    }

    [Fact]
    public void PinDisposedAfterUse()
    {
        SecurePin? handedOut = null;
        Pkcs11Key? askedFor = null;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPin(k =>
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

    [Fact]
    public void Adapter_RSAPkcs11_SignData_UsesSessionSource()
    {
        Pkcs11Key? askedFor = null;
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession();
        session.ContextAuthentication = ContextAuthentication.FromPin(k =>
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
        using Pkcs11Session fromSlot = Slot.OpenSession();

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
        Assert.Throws<ArgumentNullException>(() => ContextAuthentication.FromPin(null!));
        Assert.Same(ContextAuthentication.Pinpad, ContextAuthentication.Pinpad);
    }
}
