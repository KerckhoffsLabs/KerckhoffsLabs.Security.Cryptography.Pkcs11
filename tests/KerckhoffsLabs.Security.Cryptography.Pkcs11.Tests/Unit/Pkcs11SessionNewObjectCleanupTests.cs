using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// A call that creates objects on the token and then fails before it can hand back the key it made (the
/// token won't say what it created) destroys those objects, so a token object no one holds a handle to
/// isn't left behind. The failure is still the caller's to see.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionNewObjectCleanupTests
{
    [Fact]
    public void GenerateKeyPair_ReadingTheNewPairFails_DestroysBothHalves()
    {
        using var module = new NewObjectModule();
        using var scope = module.OpenSession();
        using ObjectTemplate pub = ObjectTemplate.Empty().Build();
        using ObjectTemplate priv = ObjectTemplate.Empty().Build();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => scope.Session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pub, priv));

        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        Assert.Equal([NewObjectModule.PublicKey, NewObjectModule.PrivateKey], module.Destroyed.Order());
    }

    [Fact]
    public void GenerateKey_ReadingTheNewKeyFails_DestroysIt()
    {
        using var module = new NewObjectModule();
        using var scope = module.OpenSession();
        using ObjectTemplate template = ObjectTemplate.Empty().Build();

        Assert.ThrowsAny<Pkcs11Exception>(() => scope.Session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template));

        Assert.Equal([NewObjectModule.SecretKey], module.Destroyed);
    }

    [Fact]
    public void ImportKey_ReadingTheNewKeyFails_DestroysIt()
    {
        using var module = new NewObjectModule();
        using var scope = module.OpenSession();
        using ObjectTemplate template = ObjectTemplate.Empty().Build();

        Assert.ThrowsAny<Pkcs11Exception>(() => scope.Session.ImportKey(template));

        Assert.Equal([NewObjectModule.SecretKey], module.Destroyed);
    }

    // The objects stay unreachable if the destroy itself fails; the caller still sees the first failure.
    [Fact]
    public void GenerateKeyPair_DestroyAlsoFails_ThrowsTheReadFailure()
    {
        using var module = new NewObjectModule { DestroyRv = CKR.CKR_ACTION_PROHIBITED };
        using var scope = module.OpenSession();
        using ObjectTemplate pub = ObjectTemplate.Empty().Build();
        using ObjectTemplate priv = ObjectTemplate.Empty().Build();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => scope.Session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pub, priv));

        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        Assert.Equal(2, module.Destroyed.Count);
    }

    private sealed class NewObjectModule : FakeModule
    {
        public const ulong SecretKey = 5, PublicKey = 6, PrivateKey = 7;

        public CKR DestroyRv { get; init; } = CKR.CKR_OK;
        public List<ulong> Destroyed { get; } = [];

        protected override bool ReleasedByFinalize => true;

        public SessionScope OpenSession()
        {
            Pkcs11Library library = Load();
            LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
            var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: (ulong)NewSessionHandle(), policy: CryptoPolicy.AllowInsecure);
            return new SessionScope(new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), core), library);
        }

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        { key = (NativeCULong)SecretKey; return CKR.CKR_OK; }

        protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
        { objectId = (NativeCULong)SecretKey; return CKR.CKR_OK; }

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        { publicKey = (NativeCULong)PublicKey; privateKey = (NativeCULong)PrivateKey; return CKR.CKR_OK; }

        // The token made the objects but fails every read of them.
        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
            => CKR.CKR_DEVICE_ERROR;

        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
        {
            Destroyed.Add((ulong)objectId);
            return DestroyRv;
        }
    }

    private sealed class SessionScope(Pkcs11Session session, Pkcs11Library library) : IDisposable
    {
        public Pkcs11Session Session { get; } = session;

        public void Dispose()
        {
            Session.Dispose();
            library.Dispose();
        }
    }
}
