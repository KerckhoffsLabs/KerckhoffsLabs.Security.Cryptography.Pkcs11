using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// PKCS#11 v3.2 <c>C_Logout</c>: "all of the application's handles to private objects become invalid (even if a
/// user is later logged back into the token)". A key, object or certificate wrapper that is private (<c>CKA_PRIVATE</c>)
/// is tied to the login it was found or made under, and once that login ends it refuses to send its handle, which
/// the module may since have given to another object. Public objects are unaffected. A login the module reports
/// gone (its anchor session lost) ends at once, and a new one can be made.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class PrivateHandleAfterLogoutTests : IDisposable
{
    private static readonly Mechanism Hmac = new(CKM.CKM_SHA256_HMAC);

    private readonly LoginTokenModule _module = new();
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public PrivateHandleAfterLogoutTests()
    {
        _module.AddObject(CKO.CKO_SECRET_KEY, "private-key", isPrivate: true, keyType: CKK.CKK_GENERIC_SECRET);
        _module.AddObject(CKO.CKO_SECRET_KEY, "public-key", isPrivate: false, keyType: CKK.CKK_GENERIC_SECRET);
        _module.AddObject(CKO.CKO_DATA, "public-data", isPrivate: false, value: [1, 2, 3]);
        _module.AddObject(CKO.CKO_DATA, "private-data", isPrivate: true, value: [4, 5, 6]);
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

    private static Pkcs11Object OpenData(Pkcs11Session session, string label)
    {
        using ObjectTemplate filter = ObjectTemplate.ForData().Label(label).Build();
        return session.OpenObject(filter);
    }

    [Fact]
    public void PrivateKey_AfterLastHolderLogsOut_RefusedWithNoNativeCall()
    {
        // Found through a session that holds no login, while a login is held: tied to that login all the same.
        using Pkcs11Session session = Slot.OpenSession();
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Key key = session.OpenKey("private-key");
        Assert.True(key.IsPrivate);
        key.Sign(Hmac, "data"u8);

        login.Dispose(); // the last holder: C_Logout, and the generation stays as it was
        Assert.Equal(1, _module.LogoutCalls);
        int signInits = _module.CallCount("C_SignInit");
        int reads = _module.CallCount("C_GetAttributeValue");

        var ex = Assert.Throws<ObjectDisposedException>(() => key.Sign(Hmac, "data"u8));
        Assert.Contains("login", ex.Message, StringComparison.Ordinal);
        Assert.Throws<ObjectDisposedException>(() => key.GetAttributeValue(CKA.CKA_LABEL));
        Assert.Throws<ObjectDisposedException>(() => key.Destroy());

        Assert.Equal(signInits, _module.CallCount("C_SignInit"));
        Assert.Equal(reads, _module.CallCount("C_GetAttributeValue"));
        Assert.Equal(0, _module.CallCount("C_DestroyObject"));
    }

    private static readonly Mechanism Pss = new(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));
    private static readonly Mechanism Oaep = new(CKM.CKM_RSA_PKCS_OAEP, new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256));

    // An RSA pair under one label and CKA_ID, so a lookup pairs the halves; the public half private or not.
    private void AddRsaPair(string label, bool publicHalfIsPrivate)
    {
        var id = new Dictionary<CKA, byte[]> { [CKA.CKA_ID] = [0x01] };
        _module.AddObject(CKO.CKO_PRIVATE_KEY, label, isPrivate: true, keyType: CKK.CKK_RSA, more: id);
        _module.AddObject(CKO.CKO_PUBLIC_KEY, label, isPrivate: publicHalfIsPrivate, keyType: CKK.CKK_RSA, more: id);
    }

    // C_Logout invalidates private handles only: the pair's public half keeps working, its private half does not.
    [Fact]
    public void KeyPair_AfterLogout_PublicHalfStillWorks_PrivateHalfRefused()
    {
        AddRsaPair("pair", publicHalfIsPrivate: false);
        using Pkcs11Session session = Slot.OpenSession();
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Key pair = session.OpenKey("pair");
        Assert.True(pair.IsPrivate);

        login.Dispose();
        int signInits = _module.CallCount("C_SignInit");
        int decryptInits = _module.CallCount("C_DecryptInit");
        int reads = _module.CallCount("C_GetAttributeValue");

        Assert.True(pair.Verify(Pss, "data"u8, new byte[256]));
        Assert.Equal([1, 2, 3], pair.Encrypt(Oaep, [1, 2, 3]));
        Assert.Equal(1, _module.CallCount("C_VerifyInit"));
        Assert.Equal(1, _module.CallCount("C_EncryptInit"));

        var sign = Assert.Throws<ObjectDisposedException>(() => pair.Sign(Pss, "data"u8));
        Assert.Contains("login", sign.Message, StringComparison.Ordinal);
        Assert.Throws<ObjectDisposedException>(() => pair.Decrypt(Oaep, new byte[256]));
        Assert.Throws<ObjectDisposedException>(() => pair.GetAttributeValue(KeyHandlePart.Private, CKA.CKA_LABEL));
        Assert.Equal(signInits, _module.CallCount("C_SignInit"));
        Assert.Equal(decryptInits, _module.CallCount("C_DecryptInit"));
        Assert.Equal(reads, _module.CallCount("C_GetAttributeValue"));

        // The public half still reads.
        using var label = pair.GetAttributeValue(KeyHandlePart.Public, CKA.CKA_LABEL);
        Assert.Equal("pair", label[0].GetValueAsString());
    }

    [Fact]
    public void KeyPair_WithAPrivatePublicHalf_AfterLogout_RefusedOnBothHalves()
    {
        AddRsaPair("pair", publicHalfIsPrivate: true);
        using Pkcs11Session session = Slot.OpenSession();
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Key pair = session.OpenKey("pair");

        login.Dispose();

        Assert.Throws<ObjectDisposedException>(() => pair.Verify(Pss, "data"u8, new byte[256]));
        Assert.Throws<ObjectDisposedException>(() => pair.Encrypt(Oaep, [1, 2, 3]));
        Assert.Throws<ObjectDisposedException>(() => pair.Sign(Pss, "data"u8));
        Assert.Throws<ObjectDisposedException>(() => pair.Decrypt(Oaep, new byte[256]));
        Assert.Equal(0, _module.CallCount("C_VerifyInit"));
        Assert.Equal(0, _module.CallCount("C_EncryptInit"));
        Assert.Equal(0, _module.CallCount("C_SignInit"));
        Assert.Equal(0, _module.CallCount("C_DecryptInit"));
    }

    // FindCertificates holds the login gate from its search through the reads that wrap each certificate, so a
    // logout asked for meanwhile waits for it, and the certificate is tied to the login it was found under.
    // Synchronized on state, not time: the search does not go on until the logout is blocked on the gate, and what
    // the read sees is captured inside the read itself (once FindCertificates returns, the logout may run at once).
    [Fact]
    public void FindCertificates_LogoutDuringTheSearch_WaitsForIt()
    {
        byte[] der = SelfSigned();
        ulong handle = _module.AddObject(CKO.CKO_CERTIFICATE, "cert", isPrivate: true, value: der,
            more: new Dictionary<CKA, byte[]> { [CKA.CKA_CERTIFICATE_TYPE] = LoginTokenModule.Ulong((ulong)CKC.CKC_X_509) });
        using Pkcs11Session session = Slot.OpenSession();
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        TokenLoginRecord record = session.Core.LoginRecord;

        Thread? logout = null;
        bool blocked = false;
        _module.DuringFind = () =>
        {
            _module.DuringFind = null;
            logout = new Thread(login.Dispose);
            logout.Start();
            blocked = SpinWait.SpinUntil(() => record.WaitingForExclusiveGate > 0, TimeSpan.FromSeconds(60));
        };
        int logoutsDuringRead = -1;
        int waitingDuringRead = -1;
        _module.DuringGetAttributeValue = objectHandle =>
        {
            if (objectHandle != handle)
                return;
            logoutsDuringRead = _module.LogoutCalls;
            waitingDuringRead = record.WaitingForExclusiveGate;
        };

        using ReadOnlyDisposableList<Pkcs11Certificate> certificates = session.FindCertificates();
        Assert.True(logout!.Join(TimeSpan.FromSeconds(60)));

        Assert.True(blocked, "the logout never blocked on the gate the search holds");
        Assert.Equal(0, logoutsDuringRead);  // the certificate was read while still logged in
        Assert.Equal(1, waitingDuringRead);  // with the logout still waiting for the search
        Assert.Equal(1, _module.LogoutCalls);

        Pkcs11Certificate certificate = Assert.Single(certificates);
        Assert.True(certificate.IsPrivate);
        var ex = Assert.Throws<ObjectDisposedException>(certificate.Destroy);
        Assert.Contains("login", ex.Message, StringComparison.Ordinal);
    }

    private static byte[] SelfSigned()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=login-test", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return certificate.RawData;
    }

    [Fact]
    public void PrivateKey_WhileItsLoginIsHeld_StillWorks_AfterAnotherHolderGoes()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        using Pkcs11Key key = session.OpenKey("private-key");

        Slot.Login(TokenUser.User, _pin).Dispose(); // a share comes and goes; the login stays

        Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Hmac, "data"u8).Length);
    }

    [Fact]
    public void PublicObject_AfterLogout_StillWorks()
    {
        using Pkcs11Session session = Slot.OpenSession();
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Key key = session.OpenKey("public-key");
        using Pkcs11Object data = OpenData(session, "public-data");
        Assert.False(key.IsPrivate);
        Assert.False(data.IsPrivate);

        login.Dispose();

        Assert.Equal([1, 2, 3], data.GetValue());
        Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Hmac, "data"u8).Length);
    }

    [Fact]
    public void PrivateKey_AfterRelogin_StillRefused()
    {
        using Pkcs11Session session = Slot.OpenSession();
        Pkcs11Key key;
        using (Slot.Login(TokenUser.User, _pin))
            key = session.OpenKey("private-key");

        using Pkcs11Login again = Slot.Login(TokenUser.User, _pin);
        int signInits = _module.CallCount("C_SignInit");

        using (key)
        {
            var ex = Assert.Throws<ObjectDisposedException>(() => key.Sign(Hmac, "data"u8));
            Assert.Contains("login", ex.Message, StringComparison.Ordinal);
        }
        Assert.Equal(signInits, _module.CallCount("C_SignInit"));

        // Found again under the new login, it works.
        using Pkcs11Key fresh = session.OpenKey("private-key");
        Assert.Equal(LoginTokenModule.SignatureLength, fresh.Sign(Hmac, "data"u8).Length);
    }

    [Fact]
    public void PrivateDataObject_AfterLogout_Refused()
    {
        using Pkcs11Session session = Slot.OpenSession();
        Pkcs11Object data;
        using (Slot.Login(TokenUser.User, _pin))
        {
            data = OpenData(session, "private-data");
            Assert.True(data.IsPrivate);
            Assert.Equal([4, 5, 6], data.GetValue());
        }
        int reads = _module.CallCount("C_GetAttributeValue");

        using (data)
        {
            var ex = Assert.Throws<ObjectDisposedException>(() => data.GetValue());
            Assert.Contains("login", ex.Message, StringComparison.Ordinal);
            Assert.Throws<ObjectDisposedException>(() => data.Destroy());
        }
        Assert.Equal(reads, _module.CallCount("C_GetAttributeValue"));
    }

    [Fact]
    public void CreatedPrivateObject_AfterLogout_Refused()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = Slot.OpenSession(SessionAccess.ReadWrite);
        using ObjectTemplate template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_DATA).Attribute(CKA.CKA_PRIVATE, true).Label("made").Build();
        using Pkcs11Object created = session.CreateObject(template);
        Assert.True(created.IsPrivate);

        login.Dispose();

        Assert.Throws<ObjectDisposedException>(() => created.GetValue());
    }

    [Fact]
    public void PrivateKey_FoundWithNoLogin_RefusedOnceALoginStarts()
    {
        // A module that shows a private object to a public session breaks the spec; the wrapper then holds it
        // to the login state it was found in: no login. Any login after that ends that state.
        using Pkcs11Session session = Slot.OpenSession();
        using Pkcs11Key key = new Pkcs11Key(session, new ObjectHandle(0x9999), ObjectHandle.Invalid,
                CKK.CKK_GENERIC_SECRET, "k", [])
            .WithLoginStamp(privateHalfIsPrivate: true, publicHalfIsPrivate: false,
                loginStamp: session.Core.LoginRecord.CurrentStamp());
        Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Hmac, "data"u8).Length);

        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);

        Assert.Throws<ObjectDisposedException>(() => key.Sign(Hmac, "data"u8));
    }

    [Fact]
    public void AnchorLost_EndsLogin_NewLoginSucceeds()
    {
        using Pkcs11Session session = Slot.OpenSession();
        using Pkcs11Login first = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Key key = session.OpenKey("private-key");
        session.Dispose(); // so the anchor is the application's only session

        var anchor = Assert.Single(_module.OpenSessions);
        _module.FailSession(anchor.Handle, CKR.CKR_DEVICE_REMOVED);

        // The anchor's next call (a share's C_Login) reports it lost: that login is over, and the same Login
        // then logs in from scratch, on a new anchor.
        using Pkcs11Login second = Slot.Login(TokenUser.User, _pin);
        Assert.False(first.IsActive);
        Assert.True(second.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
        var newAnchor = Assert.Single(_module.OpenSessions); // the lost anchor was closed
        Assert.NotEqual(anchor.Handle, newAnchor.Handle);

        // The old login's holder is inactive: releasing it sends nothing.
        int logouts = _module.LogoutCalls;
        first.Dispose();
        Assert.Equal(logouts, _module.LogoutCalls);
        Assert.True(second.IsActive);
        Assert.Throws<ObjectDisposedException>(() => key.Sign(Hmac, "data"u8));
    }

    [Fact]
    public void TokenReinserted_NextLogin_LogsInAgainAndWorks()
    {
        // The long-lived pattern: log in once, open sessions from the login. Then the token is pulled and put
        // back (or the HSM fails over): the module drops every session and the login.
        using Pkcs11Login first = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session oldSession = first.OpenSession();
        using Pkcs11Key oldKey = oldSession.OpenKey("private-key");
        oldKey.Sign(Hmac, "data"u8);
        _module.ReinsertToken();

        // Nothing has touched the anchor yet, so the old login cannot know.
        Assert.True(first.IsActive);

        // Logging in again finds the anchor lost, ends that login, and logs in afresh: one call, no exception.
        int logins = _module.LoginCalls;
        using Pkcs11Login second = Slot.Login(TokenUser.User, _pin);
        Assert.True(second.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
        Assert.Equal(logins + 2, _module.LoginCalls); // the share's C_Login on the lost anchor, then the fresh one

        // The old login, its sessions and its private handles stay ended.
        Assert.False(first.IsActive);
        Assert.Throws<ObjectDisposedException>(() => first.OpenSession());
        int signInits = _module.CallCount("C_SignInit");
        Assert.Throws<ObjectDisposedException>(() => oldKey.Sign(Hmac, "data"u8));
        Assert.Equal(signInits, _module.CallCount("C_SignInit"));

        // The new login works.
        using (Pkcs11Session session = second.OpenSession())
        using (Pkcs11Key key = session.OpenKey("private-key"))
            Assert.Equal(LoginTokenModule.SignatureLength, key.Sign(Hmac, "data"u8).Length);

        // Releasing the old holders sends no C_Logout, and leaves the new login in place.
        int logouts = _module.LogoutCalls;
        oldSession.Dispose();
        first.Dispose();
        Assert.Equal(logouts, _module.LogoutCalls);
        Assert.True(second.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    [Fact]
    public void UserNotLoggedIn_FromAnOperation_DoesNotEndTheLogin()
    {
        using Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        using Pkcs11Session session = login.OpenSession();
        var anchor = _module.OpenSessions[0];
        _module.FailSession(anchor.Handle, CKR.CKR_USER_NOT_LOGGED_IN);

        var ex = Assert.Throws<Pkcs11AuthenticationException>(() => Slot.Login(TokenUser.User, _pin));

        Assert.Equal(CKR.CKR_USER_NOT_LOGGED_IN, ex.ReturnValue);
        Assert.True(login.IsActive);
    }
}
