using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

// The mechanisms only get a call to the module that returns a handle; what they would derive or
// unwrap is not what these tests pin, so the analyzer's mechanism warnings are suppressed here.
#pragma warning disable KLPKCS11008, KLPKCS11009, KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// A module that answers <c>CKR_OK</c> but hands back <c>CK_INVALID_HANDLE</c> (0) for an object it says
/// it created or found has failed without saying so. Each call that returns a handle refuses it with a
/// <see cref="Pkcs11Exception"/>, where it comes back, rather than passing on a handle that names no object.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionCoreReturnedHandleTests
{
    private sealed class HandleFake : SessionTestModule
    {
        public ulong Returned = 0;
        public ulong ReturnedPublic = 0;
        public ulong[] Found = [0];
        public List<ulong> Destroyed { get; } = [];

        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        { key = (NativeCULong)Returned; return CKR.CKR_OK; }
        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        { publicKey = (NativeCULong)ReturnedPublic; privateKey = (NativeCULong)Returned; return CKR.CKR_OK; }
        protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
        { objectId = (NativeCULong)Returned; return CKR.CKR_OK; }
        protected override CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, ref NativeCULong newObjectId)
        { newObjectId = (NativeCULong)Returned; return CKR.CKR_OK; }
        protected override CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        { key = (NativeCULong)Returned; return CKR.CKR_OK; }
        protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        { key = (NativeCULong)Returned; return CKR.CKR_OK; }
        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
        { Destroyed.Add((ulong)objectId); return CKR.CKR_OK; }
        protected override CKR C_FindObjectsInit(NativeCULong session, CK_ATTRIBUTE[] template) => CKR.CKR_OK;
        protected override CKR C_FindObjectsFinal(NativeCULong session) => CKR.CKR_OK;
        protected override CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, ref NativeCULong count)
        {
            for (int i = 0; i < Found.Length; i++)
                objects[i] = (NativeCULong)Found[i];
            count = (NativeCULong)(ulong)Found.Length;
            return CKR.CKR_OK;
        }
    }

    private static Pkcs11SessionCore Session(HandleFake fake) => fake.CreateSession(policy: CryptoPolicy.AllowInsecure);

    private static void AssertRefused(Action call)
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(call);
        Assert.Equal(CKR.CKR_GENERAL_ERROR, ex.ReturnValue);
        Assert.Contains("CK_INVALID_HANDLE", ex.Message);
    }

    [Fact]
    public void GenerateKey_InvalidHandle_IsRefused()
    {
        using var fake = new HandleFake();
        using var s = Session(fake);
        AssertRefused(() => s.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), []));
    }

    [Fact]
    public void CreateObject_InvalidHandle_IsRefused()
    {
        using var fake = new HandleFake();
        using var s = Session(fake);
        AssertRefused(() => s.CreateObject([]));
    }

    [Fact]
    public void CopyObject_InvalidHandle_IsRefused()
    {
        using var fake = new HandleFake();
        using var s = Session(fake);
        AssertRefused(() => s.CopyObject(new ObjectHandle(1), []));
    }

    [Fact]
    public void UnwrapKey_InvalidHandle_IsRefused()
    {
        using var fake = new HandleFake();
        using var s = Session(fake);
        AssertRefused(() => s.UnwrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP_KWP), new ObjectHandle(1), new byte[40], []));
    }

    [Fact]
    public void DeriveKey_InvalidHandle_IsRefused()
    {
        using var fake = new HandleFake();
        using var s = Session(fake);
        AssertRefused(() => s.DeriveKey(new Mechanism(CKM.CKM_SHA256_KEY_DERIVATION), new ObjectHandle(1), []));
    }

    // A pair with either half missing is no pair. The half the token did create is destroyed, so the
    // refusal leaves nothing behind that no one holds a handle to.
    [Theory]
    [InlineData(0UL, 0UL, new ulong[0])]
    [InlineData(5UL, 0UL, new ulong[] { 5 })]
    [InlineData(0UL, 6UL, new ulong[] { 6 })]
    public void GenerateKeyPair_InvalidHandle_IsRefused_AndTheOtherHalfDestroyed(ulong privateKey, ulong publicKey, ulong[] destroyed)
    {
        using var fake = new HandleFake { Returned = privateKey, ReturnedPublic = publicKey };
        using var s = Session(fake);

        AssertRefused(() => s.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [], [], out _, out _));
        Assert.Equal(destroyed, fake.Destroyed);
    }

    [Fact]
    public void FindObjects_InvalidHandleListed_IsRefused()
    {
        using var fake = new HandleFake { Found = [3, 0] };
        using var s = Session(fake);
        s.FindObjectsInit([]);
        AssertRefused(() => s.FindObjects(4));
    }

    [Fact]
    public void FindAllObjects_InvalidHandleListed_IsRefused()
    {
        using var fake = new HandleFake { Found = [3, 0] };
        using var s = Session(fake);
        AssertRefused(() => s.FindAllObjects([]));
    }

    [Fact]
    public void ValidHandles_AreReturned()
    {
        using var fake = new HandleFake { Returned = 7, ReturnedPublic = 8, Found = [3, 4] };
        using var s = Session(fake);

        Assert.Equal(7UL, s.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), []).ObjectId);
        Assert.Equal(7UL, s.CreateObject([]).ObjectId);
        s.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), [], [], out ObjectHandle pub, out ObjectHandle priv);
        Assert.Equal((8UL, 7UL), (pub.ObjectId, priv.ObjectId));
        Assert.Equal([3UL, 4UL], s.FindAllObjects([]).Select(h => h.ObjectId));
        Assert.Empty(fake.Destroyed);
    }
}
