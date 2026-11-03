using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Under a policy that inspects keys, the session reads an existing key's type and size off the token and
/// submits them as a <see cref="KeyStrengthRequest"/> before the token is asked to use the key. Under any
/// other policy it reads nothing.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyStrengthGateTests
{
    private static readonly ObjectHandle Key = new(5UL);
    private static readonly ObjectHandle OtherKey = new(6UL);

    /// <summary>
    /// Answers each key's attributes from <see cref="Keys"/> and counts the reads and the calls that use a
    /// key. Every read of one attribute is two <c>C_GetAttributeValue</c> calls (length, then value).
    /// </summary>
    private sealed class StrengthFake : SessionTestModule
    {
        private int _getAttributeValueCalls;

        public Dictionary<ulong, Dictionary<CKA, ulong?>> Keys { get; } = [];

        public HashSet<CKA> Sensitive { get; } = [];

        /// <summary>Attribute reads, each the two-call sequence for one template.</summary>
        public int AttributeReads => _getAttributeValueCalls / 2;

        public int EncryptInitCalls { get; private set; }

        public int WrapCalls { get; private set; }

        public int DeriveCalls { get; private set; }

        public void SetKey(ObjectHandle handle, CKK type, ulong? valueLen)
            => Keys[handle.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)type, [CKA.CKA_VALUE_LEN] = valueLen };

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            _getAttributeValueCalls++;
            return Keys.TryGetValue((ulong)objectHandle, out var values)
                ? KeyStrengthAttributes.Answer(template, values, Sensitive)
                : CKR.CKR_OBJECT_HANDLE_INVALID;
        }

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key)
        {
            EncryptInitCalls++;
            return CKR.CKR_OK;
        }

        protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen)
        {
            int length = data.Length + 16;
            if (!encryptedData.IsNull)
                encryptedData.Span[..length].Clear();
            encryptedDataLen = (NativeCULong)(ulong)length;
            return CKR.CKR_OK;
        }

        protected override CKR C_WrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen)
        {
            WrapCalls++;
            wrappedKeyLen = (NativeCULong)40UL;
            return CKR.CKR_OK;
        }

        protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            DeriveCalls++;
            key = (NativeCULong)20UL;
            return CKR.CKR_OK;
        }
    }

    /// <summary>Recommended, but inspecting keys and allowing only AES-256 ones.</summary>
    private static ComposedCryptoPolicy AllowAllButKeyStrength() =>
        CryptoPolicy.Recommended.ToBuilder("T")
            .WithKeyStrengthRule(KeyStrengthRule.FromDelegate(
                r => r is { KeyType: CKK.CKK_AES, ValueLengthBytes: 32 }
                    ? PolicyDecision.Allow
                    : PolicyDecision.Deny("Only AES-256 keys."),
                "AES-256 only"))
            .Build();

    /// <summary>A custom policy that allows everything and knows nothing of key inspection.</summary>
    private sealed class AllowEverything : ICryptoPolicy
    {
        public string Name => "AllowEverything";
        public bool AllowsOverride => true;
        public PolicyDecision Evaluate(PolicyRequest request) => PolicyDecision.Allow;
    }

    private static byte[] Encrypt(Pkcs11SessionCore session, ObjectHandle key)
        => session.Encrypt(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 128)), key, new byte[16].AsSpan());

    private static KeyStrengthRequest RefusedRequest(Action action)
        => Assert.IsType<KeyStrengthRequest>(Assert.Throws<CryptoPolicyViolationException>(action).Request);

    [Fact]
    public void Recommended_ReadsNoAttributes()
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_AES, 16);
        using var session = fake.CreateSession();

        Encrypt(session, Key);

        Assert.Equal(0, fake.AttributeReads);
        Assert.Equal(1, fake.EncryptInitCalls);
    }

    [Fact]
    public void CustomICryptoPolicy_ReadsNoAttributes()
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_AES, 16);
        using var session = fake.CreateSession(policy: new AllowEverything());

        Encrypt(session, Key);

        Assert.Equal(0, fake.AttributeReads);
        Assert.Equal(1, fake.EncryptInitCalls);
    }

    [Fact]
    public void InspectingPolicy_RefusesAes128_BeforeTheToken()
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_AES, 16);
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(() => Encrypt(session, Key));

        Assert.Equal(CKK.CKK_AES, request.KeyType);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(KeyStrengthSource.ExistingKey, request.Source);
        Assert.Equal(0, fake.EncryptInitCalls);
    }

    [Fact]
    public void InspectingPolicy_AllowsAes256()
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_AES, 32);
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        Encrypt(session, Key);

        Assert.Equal(1, fake.EncryptInitCalls);
    }

    public enum Unreadable
    {
        /// <summary>The length sentinel CK_UNAVAILABLE_INFORMATION, with CKR_OK.</summary>
        UnavailableInformation,

        /// <summary>CKR_ATTRIBUTE_TYPE_INVALID: the token does not know CKA_VALUE_LEN for this key.</summary>
        TypeInvalid,

        /// <summary>CKR_ATTRIBUTE_SENSITIVE.</summary>
        Sensitive,

        /// <summary>A CK_ULONG value of CK_UNAVAILABLE_INFORMATION, which is no length.</summary>
        UnavailableAsValue,
    }

    [Theory]
    [InlineData(Unreadable.UnavailableInformation)]
    [InlineData(Unreadable.TypeInvalid)]
    [InlineData(Unreadable.Sensitive)]
    [InlineData(Unreadable.UnavailableAsValue)]
    public void UnreadableLength_IsRefused_BeforeTheToken(Unreadable mode)
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_AES, valueLen: null);
        switch (mode)
        {
            case Unreadable.TypeInvalid:
                fake.Keys[Key.ObjectId].Remove(CKA.CKA_VALUE_LEN);
                break;
            case Unreadable.Sensitive:
                fake.Sensitive.Add(CKA.CKA_VALUE_LEN);
                break;
            case Unreadable.UnavailableAsValue:
                fake.Keys[Key.ObjectId][CKA.CKA_VALUE_LEN] = CK.CK_UNAVAILABLE_INFORMATION;
                break;
        }
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(() => Encrypt(session, Key));

        Assert.Equal(CKK.CKK_AES, request.KeyType);
        Assert.Null(request.ValueLengthBytes);
        Assert.Equal(0, fake.EncryptInitCalls);
    }

    // An unreadable key type is reported as unknown, not left to the token.
    [Fact]
    public void UnreadableKeyType_IsRefused_BeforeTheToken()
    {
        using var fake = new StrengthFake();
        fake.Keys[Key.ObjectId] = new() { [CKA.CKA_VALUE_LEN] = 32 };
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(() => Encrypt(session, Key));

        Assert.Null(request.KeyType);
        Assert.Equal(0, fake.EncryptInitCalls);
    }

    // A handle the token rejects outright fails the read; that too is refused, not thrown as the token's error.
    [Fact]
    public void UnknownHandle_IsRefused_BeforeTheToken()
    {
        using var fake = new StrengthFake();
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(() => Encrypt(session, Key));

        Assert.Null(request.KeyType);
        Assert.Null(request.ValueLengthBytes);
        Assert.Equal(0, fake.EncryptInitCalls);
    }

    // No cache: the handle may point at a different key on the next call (Review Focus 1).
    [Fact]
    public void ExistingKey_IsReadOnEveryUse()
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_AES, 32);
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        Encrypt(session, Key);
        Encrypt(session, Key);

        Assert.Equal(4, fake.AttributeReads);
        Assert.Equal(2, fake.EncryptInitCalls);

        fake.SetKey(Key, CKK.CKK_AES, 16);
        Assert.Equal(16, RefusedRequest(() => Encrypt(session, Key)).ValueLengthBytes);
        Assert.Equal(2, fake.EncryptInitCalls);
    }

    // A key type with no size attribute in the list is described by its type alone: one read.
    [Fact]
    public void KeyTypeWithoutASizeAttribute_IsReadOnce()
    {
        using var fake = new StrengthFake();
        fake.Keys[Key.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_RSA };
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(() => Encrypt(session, Key));

        Assert.Equal(CKK.CKK_RSA, request.KeyType);
        Assert.Equal(1, fake.AttributeReads);
    }

    [Theory]
    [InlineData(CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_512)]
    [InlineData(CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_44)]
    public void PostQuantumKey_ReportsItsParameterSet(CKK type, ulong set)
    {
        using var fake = new StrengthFake();
        fake.Keys[Key.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)type, [CKA.CKA_PARAMETER_SET] = set };
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(() => Encrypt(session, Key));

        Assert.Equal(type, request.KeyType);
        Assert.Equal(set, request.ParameterSet);
        Assert.Null(request.ValueLengthBytes);
        Assert.Equal(2, fake.AttributeReads);
    }

    [Fact]
    public void HssKey_ReportsItsLevels()
    {
        using var fake = new StrengthFake();
        fake.Keys[Key.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_HSS, [CKA.CKA_HSS_LEVELS] = 2 };
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(() => Encrypt(session, Key));

        Assert.Equal(2UL, request.HssLevels);
        Assert.Equal(2, fake.AttributeReads);
    }

    [Fact]
    public void Wrap_JudgesBothKeys()
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_AES, 32);
        fake.SetKey(OtherKey, CKK.CKK_AES, 16);
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());

        KeyStrengthRequest request = RefusedRequest(
            () => session.WrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP), wrappingKeyHandle: Key, keyHandle: OtherKey));

        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(0, fake.WrapCalls);

        // And the wrapping key itself, when it is the weak one.
        Assert.Equal(16, RefusedRequest(
            () => session.WrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP), wrappingKeyHandle: OtherKey, keyHandle: Key)).ValueLengthBytes);
        Assert.Equal(0, fake.WrapCalls);
    }

    [Fact]
    public void Derive_JudgesTheBaseKey()
    {
        using var fake = new StrengthFake();
        fake.SetKey(Key, CKK.CKK_GENERIC_SECRET, 16);
        using var session = fake.CreateSession(policy: AllowAllButKeyStrength());
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Build();
        var hkdf = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC));

        KeyStrengthRequest request = RefusedRequest(() => session.DeriveKey(hkdf, Key, [.. template.Attributes]));

        Assert.Equal(CKK.CKK_GENERIC_SECRET, request.KeyType);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(0, fake.DeriveCalls);
    }

    // With no public handle, Pkcs11Key verifies in managed code from parameters it reads off the private
    // key. No session operation runs, so the key is judged there, before anything else is read.
    [Fact]
    public void ManagedVerifyFallback_JudgesThePrivateHandle()
    {
        using var fake = new StrengthFake();
        fake.Keys[Key.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_RSA };
        using Pkcs11Library library = fake.Load();
        LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
        var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1, loggerFactory: null, policy: AllowAllButKeyStrength());
        using var session = new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), core);
        using var key = new Pkcs11Key(session, Key, ObjectHandle.Invalid, CKK.CKK_RSA, "k", [0x01]);
        var pss = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, 32));

        KeyStrengthRequest request = RefusedRequest(() => key.Verify(pss, new byte[32], new byte[256]));

        Assert.Equal(CKK.CKK_RSA, request.KeyType);
        Assert.Equal(KeyStrengthSource.ExistingKey, request.Source);
        Assert.Equal(1, fake.AttributeReads);
    }
}
