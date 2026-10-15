using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// When a found or opened key looks up the other half of its pair: on the first operation that needs
/// that half, once, under the session's lease, by <c>CKA_ID</c> and <c>CKA_KEY_TYPE</c>, and again on
/// the next use if the lookup failed.
/// </summary>
/// <remarks>
/// Each search is a <c>C_FindObjectsInit</c>/<c>C_FindObjects</c>/<c>C_FindObjectsFinal</c> scan of the
/// token, so <c>C_FindObjectsInit</c> counts the searches.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11KeyCompanionTests
{
    private static readonly byte[] Data = "companion"u8.ToArray();
    private static readonly Mechanism EcdsaSha256 = new(CKM.CKM_ECDSA_SHA256);

    [Fact]
    public void FindKeys_SearchesForNoCompanion()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        for (byte i = 1; i <= 3; i++)
            GenerateEcPair(session, $"pair-{i}", [i]).Dispose();
        int searches = token.CallCount("C_FindObjectsInit");

        using var keys = FindPrivateKeys(session);

        Assert.Equal(3, keys.Count);
        Assert.Equal(searches + 1, token.CallCount("C_FindObjectsInit"));
    }

    [Fact]
    public void Verify_LooksUpThePublicKeyOnce_AndVerifiesOnTheToken()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using (Pkcs11Key pair = GenerateEcPair(session, "pair", [0x01])) { }
        using var keys = FindPrivateKeys(session);
        Pkcs11Key key = Assert.Single(keys);
        int searches = token.CallCount("C_FindObjectsInit");

        byte[] signature = key.Sign(EcdsaSha256, Data);
        Assert.Equal(searches, token.CallCount("C_FindObjectsInit")); // Sign needs only the private half

        Assert.True(key.Verify(EcdsaSha256, Data, signature));
        Assert.True(key.Verify(EcdsaSha256, Data, signature));

        Assert.Equal(searches + 1, token.CallCount("C_FindObjectsInit"));
        Assert.Equal(2, token.CallCount("C_VerifyInit"));
    }

    [Fact]
    public void PublicKey_LooksUpItsPrivateKey_WhenSigning()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using (Pkcs11Key pair = GenerateEcPair(session, "pair", [0x01])) { }
        using var filter = ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PUBLIC_KEY).Build();
        using var keys = session.FindKeys(filter);
        Pkcs11Key key = Assert.Single(keys);

        byte[] signature = key.Sign(EcdsaSha256, Data);

        Assert.True(key.Verify(EcdsaSha256, Data, signature));
    }

    // A short id reused across keys must not pair an EC key with an RSA public key that happens to be
    // found first.
    [Fact]
    public void Companion_MustHaveTheSameKeyType()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        GenerateRsaPair(session, "rsa", [0x01]).Dispose();
        ObjectHandle ecPublic;
        using (Pkcs11Key pair = GenerateEcPair(session, "ec", [0x01]))
            ecPublic = pair.PublicHandle;

        using var filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY).Label("ec").Build();
        using var keys = session.FindKeys(filter);

        Assert.Equal(ecPublic, Assert.Single(keys).PublicHandle);
    }

    // The managed verification fallback stays for keys whose public half is not on the token, and is
    // taken only once the lookup has found nothing.
    [Fact]
    public void Verify_WithNoPublicKeyOnTheToken_StillVerifiesInManagedCode()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library);
        using (Pkcs11Key pair = GenerateEcPair(session, "pair", [0x01]))
            session.Core.DestroyObject(pair.PublicHandle);
        using Pkcs11Key key = session.OpenKey("pair");
        byte[] signature = key.Sign(EcdsaSha256, Data);
        int searches = token.CallCount("C_FindObjectsInit");

        Assert.True(key.Verify(EcdsaSha256, Data, signature));

        Assert.Equal(searches + 1, token.CallCount("C_FindObjectsInit"));
        Assert.Equal(0, token.CallCount("C_VerifyInit"));
    }

    // A failed lookup is not remembered as "no companion": the next use looks again.
    [Fact]
    public void FailedLookup_IsRetriedOnTheNextUse()
    {
        using var module = new CompanionModule { FailingSearches = 1 };
        using var scope = module.OpenKey();

        Assert.ThrowsAny<Pkcs11Exception>(() => scope.Key.PublicHandle);
        Assert.Equal(CompanionModule.PublicHandle, scope.Key.PublicHandle);

        Assert.Equal(2, module.CallCount("C_FindObjectsInit"));
    }

    // While another thread holds the session, the lookup is refused like any other call on it, rather
    // than answered with "no companion" from a search still in flight.
    [Fact]
    public void Lookup_WhileAnotherThreadHoldsTheSession_IsRefused()
    {
        using var module = new CompanionModule();
        using var scope = module.OpenKey();
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var holder = new Thread(() =>
        {
            using (scope.Session.Core.AcquireExclusive())
            {
                held.Set();
                release.Wait(TestContext.Current.CancellationToken);
            }
        });
        holder.Start();
        held.Wait(TestContext.Current.CancellationToken);

        try
        {
            Assert.Throws<InvalidOperationException>(() => scope.Key.PublicHandle);
        }
        finally
        {
            release.Set();
            holder.Join();
        }

        Assert.Equal(CompanionModule.PublicHandle, scope.Key.PublicHandle);
    }

    private static ReadOnlyDisposableList<Pkcs11Key> FindPrivateKeys(Pkcs11Session session)
    {
        using var filter = ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY).Build();
        return session.FindKeys(filter);
    }

    private static Pkcs11Key GenerateEcPair(Pkcs11Session session, string label, byte[] id)
    {
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Verify().Label(label).Id(id).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Sensitive().NonExtractable().Sign().Label(label).Id(id).Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pub, priv);
    }

    private static Pkcs11Key GenerateRsaPair(Pkcs11Session session, string label, byte[] id)
    {
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_RSA).ModulusBits(2048).Verify().Label(label).Id(id).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Sensitive().NonExtractable().Sign().Label(label).Id(id).Build();
        return session.GenerateKeyPair(new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN), pub, priv);
    }

    /// <summary>
    /// A token whose every search finds one public key, <see cref="PublicHandle"/>, except the first
    /// <see cref="FailingSearches"/>, which fail with <c>CKR_DEVICE_ERROR</c>.
    /// </summary>
    private sealed class CompanionModule : FakeModule
    {
        public static readonly ObjectHandle PublicHandle = new(2);
        private bool _pending;

        public int FailingSearches { get; set; }

        protected override bool ReleasedByFinalize => true;

        /// <summary>A private EC key with id 01 whose public half has not been looked up yet.</summary>
        public KeyScope OpenKey()
        {
            Pkcs11Library library = Load();
            LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
            var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1);
            var session = new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), core);
            var key = new Pkcs11Key(session, new ObjectHandle(1), ObjectHandle.Invalid, CKK.CKK_EC, "k", [0x01],
                companionPending: true);
            return new KeyScope(key, session, library);
        }

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template)
        {
            if (FailingSearches > 0)
            {
                FailingSearches--;
                return CKR.CKR_DEVICE_ERROR;
            }
            _pending = true;
            return CKR.CKR_OK;
        }

        protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
        {
            int n = 0;
            if (_pending && objects.Length > 0)
            {
                objects[n++] = (NativeCULong)PublicHandle.ObjectId;
                _pending = false;
            }
            count = (NativeCULong)(ulong)n;
            return CKR.CKR_OK;
        }

        protected override CKR C_FindObjectsFinal(NativeCULong session) => CKR.CKR_OK;
    }

    /// <summary>The key with the session and library behind it, disposed key first.</summary>
    private sealed class KeyScope(Pkcs11Key key, Pkcs11Session session, Pkcs11Library library) : IDisposable
    {
        public Pkcs11Key Key { get; } = key;

        public Pkcs11Session Session { get; } = session;

        public void Dispose()
        {
            Key.Dispose();
            Session.Dispose();
            library.Dispose();
        }
    }
}
