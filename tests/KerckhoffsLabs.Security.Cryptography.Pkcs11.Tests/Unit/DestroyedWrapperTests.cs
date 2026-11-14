using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// BL-116. PKCS#11 v3.2 §4.4 lets a module hand a destroyed object's handle to a new object, so once a wrapper's
/// own <c>Destroy</c> has succeeded it must not send that handle again: a second <c>Destroy</c> would remove an
/// object the caller never chose, and a <c>Sign</c> would use one. Each case asserts the refusal is made before
/// the token is reached, which is what makes the guard independent of whether a given module recycles handles.
/// Only the destroying wrapper is covered; another wrapper over the same handle cannot know.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class DestroyedWrapperTests
{
    private static readonly ObjectHandle SecretKey = new(5UL);
    private static readonly ObjectHandle PrivateHalf = new(6UL);
    private static readonly ObjectHandle PublicHalf = new(7UL);

    /// <summary>Destroys whatever it is asked to, except the handles in <see cref="Refused"/>.</summary>
    private sealed class DestroyModule : FakeModule
    {
        public List<ulong> Destroyed { get; } = [];

        public HashSet<ulong> Refused { get; } = [];

        public int TotalCalls => Calls.Values.Sum();

        protected override bool ReleasedByFinalize => true;

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
        {
            if (Refused.Contains((ulong)objectId))
                return CKR.CKR_ACTION_PROHIBITED;
            Destroyed.Add((ulong)objectId);
            return CKR.CKR_OK;
        }
    }

    private static void WithSession(DestroyModule module, Action<Pkcs11Session> body)
    {
        using Pkcs11Library library = module.Load();
        LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
        var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1);
        using var session = new Pkcs11Session(library, new Pkcs11Slot(library, slotId: 1), core);
        body(session);
    }

    private static Pkcs11Key Secret(Pkcs11Session session) =>
        new(session, SecretKey, ObjectHandle.Invalid, CKK.CKK_AES, "secret", []);

    private static Pkcs11Key Pair(Pkcs11Session session) =>
        new(session, PrivateHalf, PublicHalf, CKK.CKK_EC, "pair", []);

    [Theory]
    [InlineData("Destroy")]
    [InlineData("Sign")]
    [InlineData("KeySize")]
    public void Key_UsedAfterItsOwnDestroy_IsRefusedBeforeTheToken(string use)
    {
        using var module = new DestroyModule();
        WithSession(module, session =>
        {
            using Pkcs11Key key = Secret(session);
            key.Destroy();
            int callsAfterDestroy = module.TotalCalls;

            var ex = Assert.Throws<ObjectDisposedException>(() =>
            {
                switch (use)
                {
                    case "Destroy": key.Destroy(); break;
                    case "Sign": key.Sign(new Mechanism(CKM.CKM_AES_CMAC), [1, 2, 3]); break;
                    default: _ = key.KeySize; break;
                }
            });

            Assert.Contains("Destroy()", ex.Message, StringComparison.Ordinal);
            Assert.Equal(callsAfterDestroy, module.TotalCalls);
            Assert.Equal([SecretKey.ObjectId], module.Destroyed);
        });
    }

    // The target's handle goes into C_WrapKey too: once the target's own Destroy has succeeded, that handle may name
    // another key, and wrapping it would export a key the caller never chose.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Wrap_OfATargetDestroyedOrDisposed_IsRefusedBeforeTheToken(bool destroyed)
    {
        using var module = new DestroyModule();
        WithSession(module, session =>
        {
            using Pkcs11Key wrapping = new(session, new ObjectHandle(8UL), ObjectHandle.Invalid, CKK.CKK_AES, "kek", []);
            using Pkcs11Key target = Secret(session);
            if (destroyed)
                target.Destroy();
            else
                target.Dispose();
            int calls = module.TotalCalls;

            var ex = Assert.Throws<ObjectDisposedException>(() => wrapping.Wrap(new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP), target));

            if (destroyed)
                Assert.Contains("Destroy()", ex.Message, StringComparison.Ordinal);
            Assert.Equal(calls, module.TotalCalls);
            Assert.Equal(0, module.CallCount("C_WrapKey"));
            target.Dispose();
        });
    }

    [Fact]
    public void Key_DisposedAfterItsOwnDestroy_DoesNotThrow()
    {
        using var module = new DestroyModule();
        WithSession(module, session =>
        {
            Pkcs11Key key = Secret(session);
            key.Destroy();

            Assert.Null(Record.Exception(key.Dispose));
        });
    }

    [Fact]
    public void Key_RefusedDestroy_LeavesTheKeyUsable()
    {
        using var module = new DestroyModule();
        module.Refused.Add(SecretKey.ObjectId);
        WithSession(module, session =>
        {
            using Pkcs11Key key = Secret(session);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(key.Destroy);
            Assert.Equal(CKR.CKR_ACTION_PROHIBITED, ex.ReturnValue);

            // Nothing was destroyed, so the handle still names the caller's key and a retry reaches the token.
            module.Refused.Clear();
            key.Destroy();
            Assert.Equal([SecretKey.ObjectId], module.Destroyed);
            Assert.Equal(2, module.CallCount("C_DestroyObject"));
        });
    }

    [Fact]
    public void Pair_Destroy_RemovesThePrivateHalfFirst_ThenThePublicHalf()
    {
        using var module = new DestroyModule();
        WithSession(module, session =>
        {
            using Pkcs11Key key = Pair(session);

            key.Destroy();

            Assert.Equal([PrivateHalf.ObjectId, PublicHalf.ObjectId], module.Destroyed);
            Assert.Throws<ObjectDisposedException>(key.Destroy);
            Assert.Equal(2, module.CallCount("C_DestroyObject"));
        });
    }

    [Fact]
    public void Pair_PublicHalfRefused_KeepsOnlyThePublicHalf_AndARetryDestroysOnlyIt()
    {
        using var module = new DestroyModule();
        module.Refused.Add(PublicHalf.ObjectId);
        WithSession(module, session =>
        {
            using Pkcs11Key key = Pair(session);

            var ex = Assert.ThrowsAny<Pkcs11Exception>(key.Destroy);
            Assert.Equal(CKR.CKR_ACTION_PROHIBITED, ex.ReturnValue);

            // The partial outcome is visible on the key: the private half is gone, the public half remains.
            Assert.True(key.PrivateHandle.IsInvalid);
            Assert.Equal(PublicHalf, key.PublicHandle);

            module.Refused.Clear();
            key.Destroy();

            // The retry never resends the private half's handle, which the module may already have reused.
            Assert.Equal([PrivateHalf.ObjectId, PublicHalf.ObjectId], module.Destroyed);
            Assert.Equal(3, module.CallCount("C_DestroyObject"));
            Assert.Throws<ObjectDisposedException>(key.Destroy);
        });
    }

    [Theory]
    [InlineData("Destroy")]
    [InlineData("GetValue")]
    public void Object_UsedAfterItsOwnDestroy_IsRefusedBeforeTheToken(string use)
    {
        using var module = new DestroyModule();
        WithSession(module, session =>
        {
            using var obj = new Pkcs11Object(session, SecretKey, CKO.CKO_DATA, "data", []);
            obj.Destroy();
            int callsAfterDestroy = module.TotalCalls;

            Assert.Throws<ObjectDisposedException>(() =>
            {
                if (use == "Destroy")
                    obj.Destroy();
                else
                    _ = obj.GetValue();
            });

            Assert.Equal(callsAfterDestroy, module.TotalCalls);
            Assert.Equal([SecretKey.ObjectId], module.Destroyed);
        });
    }

    [Fact]
    public void Certificate_DestroyedTwice_SecondIsRefusedBeforeTheToken_AndTheParsedCertificateRemains()
    {
        using var module = new DestroyModule();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 parsed = new CertificateRequest("CN=destroyed", ecdsa, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        WithSession(module, session =>
        {
            using var certificate = new Pkcs11Certificate(session, SecretKey, "cert", [], new X509Certificate2(parsed));
            certificate.Destroy();
            int callsAfterDestroy = module.TotalCalls;

            Assert.Throws<ObjectDisposedException>(certificate.Destroy);

            Assert.Equal(callsAfterDestroy, module.TotalCalls);
            Assert.Equal([SecretKey.ObjectId], module.Destroyed);
            Assert.Equal("CN=destroyed", certificate.Certificate.Subject);
        });
    }
}
