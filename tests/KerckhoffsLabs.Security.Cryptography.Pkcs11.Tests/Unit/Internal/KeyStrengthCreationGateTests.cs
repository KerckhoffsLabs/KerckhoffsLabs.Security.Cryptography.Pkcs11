using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Under a policy that inspects keys, a key being created is judged twice: from the caller's template
/// before the token sees it, when the template states the key's size, and from the token's own answer
/// right after it made the key. A created key that fails is destroyed and its handle never returned.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyStrengthCreationGateTests : IDisposable
{
    // The templates AesTemplate builds, disposed with the test.
    private readonly List<ObjectTemplate> _templates = [];

    public void Dispose()
    {
        foreach (ObjectTemplate template in _templates)
            template.Dispose();
    }

    private const ulong Created = 42;
    private const ulong CreatedPublic = 43;
    private const ulong CreatedPrivate = 44;
    private static readonly ObjectHandle StrongAes = new(5UL);
    private static readonly ObjectHandle WeakAes = new(6UL);
    private static readonly ObjectHandle KemPrivate = new(7UL);
    private static readonly ObjectHandle KemPublic = new(8UL);

    /// <summary>
    /// A token whose creating calls return fixed handles (<see cref="Created"/>, or the pair
    /// <see cref="CreatedPublic"/>/<see cref="CreatedPrivate"/>) and answer every handle's attributes from
    /// <see cref="Keys"/>. It counts every native call the gate could make, one per call.
    /// </summary>
    private sealed class CreationFake : SessionTestModule
    {
        public Dictionary<ulong, Dictionary<CKA, ulong?>> Keys { get; } = [];

        /// <summary>Raw <c>C_GetAttributeValue</c> calls, not reads: a read of one template is two calls.</summary>
        public int GetAttributeValueCalls { get; private set; }

        public int GenerateKeyCalls { get; private set; }
        public int GenerateKeyPairCalls { get; private set; }
        public int UnwrapCalls { get; private set; }
        public int UnwrapAuthenticatedCalls { get; private set; }
        public int DeriveCalls { get; private set; }
        public int EncapsulateCalls { get; private set; }
        public int DecapsulateCalls { get; private set; }
        public int CreateObjectCalls { get; private set; }
        public int CopyObjectCalls { get; private set; }

        public List<ulong> Destroyed { get; } = [];

        /// <summary>The handle <c>C_DeriveKey</c> returns.</summary>
        public ulong DerivedHandle { get; set; } = Created;

        /// <summary>
        /// The handles <c>C_DeriveKey</c> writes into an SP800-108 derivation's additional derived-key slots,
        /// one per slot, at the platform's CK_ULONG width.
        /// </summary>
        public ulong[] SiblingHandles { get; set; } = [];

        /// <summary>Handles whose <c>C_GetAttributeValue</c> fails with the given return value.</summary>
        public Dictionary<ulong, CKR> ReadFailures { get; } = [];

        /// <summary>What <c>C_DestroyObject</c> answers.</summary>
        public CKR DestroyResult { get; set; } = CKR.CKR_OK;

        public void SetAes(ulong handle, ulong? valueLen)
            => Keys[handle] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_AES, [CKA.CKA_VALUE_LEN] = valueLen };

        public void SetPq(ulong handle, CKK type, ulong set)
            => Keys[handle] = new() { [CKA.CKA_KEY_TYPE] = (ulong)type, [CKA.CKA_PARAMETER_SET] = set };

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            GetAttributeValueCalls++;
            if (ReadFailures.TryGetValue((ulong)objectHandle, out CKR failure))
                return failure;
            return Keys.TryGetValue((ulong)objectHandle, out var values)
                ? KeyStrengthAttributes.Answer(template, values)
                : CKR.CKR_OBJECT_HANDLE_INVALID;
        }

        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            GenerateKeyCalls++;
            key = (NativeCULong)Created;
            return CKR.CKR_OK;
        }

        protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
        {
            GenerateKeyPairCalls++;
            publicKey = (NativeCULong)CreatedPublic;
            privateKey = (NativeCULong)CreatedPrivate;
            return CKR.CKR_OK;
        }

        protected override CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            UnwrapCalls++;
            key = (NativeCULong)Created;
            return CKR.CKR_OK;
        }

        protected override CKR C_UnwrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> associatedData, ref NativeCULong key)
        {
            UnwrapAuthenticatedCalls++;
            key = (NativeCULong)Created;
            return CKR.CKR_OK;
        }

        protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            DeriveCalls++;
            key = (NativeCULong)DerivedHandle;
            if (SiblingHandles.Length > 0)
            {
                var kdf = UnmanagedMemory.Read<CK_SP800_108_KDF_PARAMS>(mechanism.Parameter);
                int size = UnmanagedMemory.SizeOf<CK_DERIVED_KEY>();
                for (int j = 0; j < (int)(ulong)kdf.AdditionalDerivedKeys; j++)
                {
                    var slot = UnmanagedMemory.Read<CK_DERIVED_KEY>(IntPtr.Add(kdf.AdditionalDerivedKeysPtr, j * size));
                    WriteHandle(slot.Key, SiblingHandles[j]);
                }
            }
            return CKR.CKR_OK;
        }

        private static void WriteHandle(IntPtr slot, ulong handle)
        {
            Span<byte> bytes = stackalloc byte[8];
            if (UnmanagedMemory.NativeULongSize == 4)
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes, checked((uint)handle));
            else
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(bytes, handle);
            UnmanagedMemory.Write(slot, bytes[..UnmanagedMemory.NativeULongSize]);
        }

        protected override CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key)
        {
            EncapsulateCalls++;
            if (!ciphertext.IsNull)
                ciphertext.Span[..1568].Clear();
            ciphertextLen = (NativeCULong)1568UL;
            key = (NativeCULong)Created;
            return CKR.CKR_OK;
        }

        protected override CKR C_DecapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> ciphertext, ref NativeCULong key)
        {
            DecapsulateCalls++;
            key = (NativeCULong)Created;
            return CKR.CKR_OK;
        }

        protected override CKR C_CreateObject(NativeCULong session, CK_ATTRIBUTE[] template, ref NativeCULong objectId)
        {
            CreateObjectCalls++;
            objectId = (NativeCULong)Created;
            return CKR.CKR_OK;
        }

        protected override CKR C_CopyObject(NativeCULong session, NativeCULong objectId, CK_ATTRIBUTE[] template, ref NativeCULong newObjectId)
        {
            CopyObjectCalls++;
            newObjectId = (NativeCULong)Created;
            return CKR.CKR_OK;
        }

        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
        {
            Destroyed.Add((ulong)objectId);
            if (DestroyResult == CKR.CKR_OK)
                Keys.Remove((ulong)objectId);
            return DestroyResult;
        }
    }

    /// <summary>Recommended, but inspecting keys: AES-256, ML-KEM-1024 and ML-DSA-87 only.</summary>
    private static ComposedCryptoPolicy StrongKeysOnly() =>
        CryptoPolicy.Recommended.ToBuilder("T")
            .WithKeyStrengthRule(KeyStrengthRule.FromDelegate(
                r => r switch
                {
                    { KeyType: CKK.CKK_AES, ValueLengthBytes: 32 } => PolicyDecision.Allow,
                    { KeyType: CKK.CKK_ML_KEM, ParameterSet: (ulong)CkpMlKem.CKP_ML_KEM_1024 } => PolicyDecision.Allow,
                    { KeyType: CKK.CKK_ML_DSA, ParameterSet: (ulong)CkpMlDsa.CKP_ML_DSA_87 } => PolicyDecision.Allow,
                    _ => PolicyDecision.Deny("Too weak."),
                },
                "strong keys only"))
            .Build();

    private static CryptoPolicyViolationException Refusal(Action action)
        => Assert.Throws<CryptoPolicyViolationException>(action);

    private static KeyStrengthRequest RefusedRequest(Action action)
        => Assert.IsType<KeyStrengthRequest>(Refusal(action).Request);

    private List<ObjectAttribute> AesTemplate(int? valueLen = null)
    {
        using var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Encrypt().Decrypt();
        if (valueLen is { } len)
            builder.ValueLen(len);
        ObjectTemplate template = builder.Build();
        _templates.Add(template);
        return [.. template.Attributes];
    }

    private ObjectHandle GenerateAes(Pkcs11SessionCore session, int? valueLen = null)
        => session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), AesTemplate(valueLen));

    private ObjectHandle Unwrap(Pkcs11SessionCore session)
        => session.UnwrapKey(new Mechanism(CKM.CKM_AES_KEY_WRAP), StrongAes, new byte[40], AesTemplate());

    [Fact]
    public void GenerateAes_TemplateWith16Bytes_IsRefused_BeforeTheToken()
    {
        using var fake = new CreationFake();
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        KeyStrengthRequest request = RefusedRequest(() => GenerateAes(session, 16));

        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(CKK.CKK_AES, request.KeyType);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(0, fake.GenerateKeyCalls);
        Assert.Empty(fake.Destroyed);
    }

    // The key type comes from the mechanism when the template does not state it.
    [Fact]
    public void GenerateAes_TemplateWith16BytesAndNoKeyType_TakesTheTypeFromTheMechanism()
    {
        using var fake = new CreationFake();
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var len = new ObjectAttribute(CKA.CKA_VALUE_LEN, 16UL);

        KeyStrengthRequest request = RefusedRequest(() => session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), [len]));

        Assert.Equal(CKK.CKK_AES, request.KeyType);
        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(0, fake.GenerateKeyCalls);
    }

    [Fact]
    public void GenerateAes_TemplateWithoutLength_IsJudgedAfterCreation()
    {
        using var fake = new CreationFake();
        fake.SetAes(Created, 16);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        KeyStrengthRequest request = RefusedRequest(() => GenerateAes(session));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(1, fake.GenerateKeyCalls);
        Assert.Equal([Created], fake.Destroyed);
    }

    [Fact]
    public void GenerateAes256_PassesBothChecks_AndIsReturned()
    {
        using var fake = new CreationFake();
        fake.SetAes(Created, 32);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        ObjectHandle key = GenerateAes(session, 32);

        Assert.Equal(Created, key.ObjectId);
        Assert.Empty(fake.Destroyed);
        // The post-check reads the key the token made, even when the template already passed: two reads.
        Assert.Equal(4, fake.GetAttributeValueCalls);
    }

    [Fact]
    public void Unwrap_CreatedAes128_IsDestroyed_AndRefused()
    {
        using var fake = new CreationFake();
        fake.SetAes(StrongAes.ObjectId, 32);
        fake.SetAes(Created, 16);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        KeyStrengthRequest request = RefusedRequest(() => Unwrap(session));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(1, fake.UnwrapCalls);
        Assert.Equal([Created], fake.Destroyed);
    }

    [Fact]
    public void Unwrap_CreatedAes256_IsReturned()
    {
        using var fake = new CreationFake();
        fake.SetAes(StrongAes.ObjectId, 32);
        fake.SetAes(Created, 32);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        ObjectHandle key = Unwrap(session);

        Assert.Equal(Created, key.ObjectId);
        Assert.Empty(fake.Destroyed);
    }

    [Fact]
    public void KeyPairWithoutParameterSet_IsJudgedAfterCreation_AndBothHalvesDestroyed()
    {
        using var fake = new CreationFake();
        fake.SetPq(CreatedPublic, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_768);
        fake.SetPq(CreatedPrivate, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_768);
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM).Build();

        ObjectHandle publicHandle = new(1UL), privateHandle = new(1UL);
        KeyStrengthRequest request = RefusedRequest(() => session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), [.. pub.Attributes], [.. priv.Attributes], out publicHandle, out privateHandle));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal((ulong)CkpMlKem.CKP_ML_KEM_768, request.ParameterSet);
        Assert.Equal(1, fake.GenerateKeyPairCalls);
        Assert.Equal([CreatedPublic, CreatedPrivate], fake.Destroyed);
        Assert.Equal(1UL, publicHandle.ObjectId);
        Assert.Equal(1UL, privateHandle.ObjectId);
    }

    // Only one half failing is enough: the pair goes together.
    [Fact]
    public void KeyPair_OnlyThePrivateHalfFails_BothHalvesDestroyed()
    {
        using var fake = new CreationFake();
        fake.SetPq(CreatedPublic, CKK.CKK_ML_DSA, (ulong)CkpMlDsa.CKP_ML_DSA_87);
        fake.Keys[CreatedPrivate] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_ML_DSA, [CKA.CKA_PARAMETER_SET] = null };
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA).Build();

        KeyStrengthRequest request = RefusedRequest(() => session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), [.. pub.Attributes], [.. priv.Attributes], out _, out _));

        Assert.Null(request.ParameterSet);
        Assert.Equal([CreatedPublic, CreatedPrivate], fake.Destroyed);
    }

    [Fact]
    public void KeyPairTemplateWithMlDsa65_IsRefused_BeforeTheToken()
    {
        using var fake = new CreationFake();
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_ML_DSA)
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)CkpMlDsa.CKP_ML_DSA_65).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_DSA).Build();

        KeyStrengthRequest request = RefusedRequest(() => session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_DSA_KEY_PAIR_GEN), [.. pub.Attributes], [.. priv.Attributes], out _, out _));

        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(CKK.CKK_ML_DSA, request.KeyType);
        Assert.Equal((ulong)CkpMlDsa.CKP_ML_DSA_65, request.ParameterSet);
        Assert.Equal(0, fake.GenerateKeyPairCalls);
        Assert.Equal(0, fake.GetAttributeValueCalls);
    }

    [Fact]
    public void Decapsulate_SharedKeyOfUnreportedLength_IsDestroyed()
    {
        using var fake = new CreationFake();
        fake.SetPq(KemPrivate.ObjectId, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_1024);
        fake.SetAes(Created, valueLen: null);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        KeyStrengthRequest request = RefusedRequest(
            () => session.DecapsulateKey(new Mechanism(CKM.CKM_ML_KEM), KemPrivate, new byte[1568], AesTemplate()));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Null(request.ValueLengthBytes);
        Assert.Equal(1, fake.DecapsulateCalls);
        Assert.Equal([Created], fake.Destroyed);
    }

    [Fact]
    public void Encapsulate_SharedAes128_IsDestroyed()
    {
        using var fake = new CreationFake();
        fake.SetPq(KemPublic.ObjectId, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_1024);
        fake.SetAes(Created, 16);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        KeyStrengthRequest request = RefusedRequest(
            () => session.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), KemPublic, AesTemplate(), expectedCiphertextLen: 1568));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal(1, fake.EncapsulateCalls);
        Assert.Equal([Created], fake.Destroyed);
    }

    [Fact]
    public void Encapsulate_TemplateWith16Bytes_IsRefused_BeforeTheToken()
    {
        using var fake = new CreationFake();
        fake.SetPq(KemPublic.ObjectId, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_1024);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        KeyStrengthRequest request = RefusedRequest(
            () => session.EncapsulateKey(new Mechanism(CKM.CKM_ML_KEM), KemPublic, AesTemplate(16), expectedCiphertextLen: 1568));

        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(0, fake.EncapsulateCalls);
    }

    [Fact]
    public void UnwrapAuthenticated_CreatedAes128_IsDestroyed()
    {
        using var fake = new CreationFake();
        fake.SetAes(StrongAes.ObjectId, 32);
        fake.SetAes(Created, 16);
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        KeyStrengthRequest request = RefusedRequest(() => session.UnwrapKeyAuthenticated(
            new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 128)), StrongAes, new byte[48], [0x01], AesTemplate()));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal(1, fake.UnwrapAuthenticatedCalls);
        Assert.Equal([Created], fake.Destroyed);
    }

    [Fact]
    public void Derive_CreatedAes128_IsDestroyed()
    {
        using var fake = new CreationFake();
        fake.Keys[StrongAes.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_GENERIC_SECRET, [CKA.CKA_VALUE_LEN] = 32 };
        fake.SetAes(Created, 16);
        var policy = CryptoPolicy.Recommended.ToBuilder("T")
            .WithKeyStrengthRule(KeyStrengthRule.FromDelegate(
                r => r.ValueLengthBytes == 32 ? PolicyDecision.Allow : PolicyDecision.Deny("Too weak."), "32 bytes"))
            .Build();
        using var session = fake.CreateSession(policy: policy);
        var hkdf = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC));

        KeyStrengthRequest request = RefusedRequest(() => session.DeriveKey(hkdf, StrongAes, AesTemplate()));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal(1, fake.DeriveCalls);
        Assert.Equal([Created], fake.Destroyed);
    }

    // A derivation that hands its keys back in the mechanism parameters leaves CK_INVALID_HANDLE as the
    // result: there is no object to read or destroy.
    [Fact]
    public void Derive_ReturningTheInvalidHandle_ReadsAndDestroysNothing()
    {
        using var fake = new CreationFake { DerivedHandle = CK.CK_INVALID_HANDLE };
        fake.Keys[StrongAes.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_AES, [CKA.CKA_VALUE_LEN] = 32 };
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        var hkdf = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC));

        ObjectHandle derived = session.DeriveKey(hkdf, StrongAes, AesTemplate());

        Assert.True(derived.IsInvalid);
        // The base key's two reads only.
        Assert.Equal(4, fake.GetAttributeValueCalls);
        Assert.Empty(fake.Destroyed);
    }

    [Fact]
    public void Derive_TemplateWith16Bytes_IsRefused_BeforeTheToken()
    {
        using var fake = new CreationFake();
        fake.Keys[StrongAes.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_AES, [CKA.CKA_VALUE_LEN] = 32 };
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        var hkdf = new Mechanism(CKM.CKM_HKDF_DERIVE, CkmHkdfParams.WithoutSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC));

        KeyStrengthRequest request = RefusedRequest(() => session.DeriveKey(hkdf, StrongAes, AesTemplate(16)));

        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(0, fake.DeriveCalls);
    }

    private const ulong SiblingA = 50;
    private const ulong SiblingB = 51;

    /// <summary>Recommended, but inspecting keys and allowing any key of 32 bytes (the base key is a generic secret).</summary>
    private static ComposedCryptoPolicy Only32Bytes() =>
        CryptoPolicy.Recommended.ToBuilder("T")
            .WithKeyStrengthRule(KeyStrengthRule.FromDelegate(
                r => r.ValueLengthBytes == 32 ? PolicyDecision.Allow : PolicyDecision.Deny("Too weak."), "32 bytes"))
            .Build();

    /// <summary>A counter-mode SP800-108 derivation with one additional derived key per template.</summary>
    private static CkmSp800108KdfParams Sp800108(params List<ObjectAttribute>[] siblings)
    {
        var builder = CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
            .IterationCounter(widthInBits: 32, littleEndian: false)
            .ByteArray([0x01])
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys, widthInBits: 32, littleEndian: false);
        foreach (List<ObjectAttribute> sibling in siblings)
            builder.AddDerivedKey(sibling);
        return builder.Build();
    }

    private CreationFake Sp800108Fake(ulong? siblingBLength)
    {
        var fake = new CreationFake { SiblingHandles = [SiblingA, SiblingB] };
        fake.Keys[StrongAes.ObjectId] = new() { [CKA.CKA_KEY_TYPE] = (ulong)CKK.CKK_GENERIC_SECRET, [CKA.CKA_VALUE_LEN] = 32 };
        fake.SetAes(Created, 32);
        fake.SetAes(SiblingA, 32);
        fake.SetAes(SiblingB, siblingBLength);
        return fake;
    }

    // A sibling key is a created key too: one refused sibling takes the main key and every other sibling with it.
    [Fact]
    public void Sp800108_RefusedSibling_DestroysTheMainKeyAndEverySibling()
    {
        using CreationFake fake = Sp800108Fake(siblingBLength: 16);
        using var session = fake.CreateSession(policy: Only32Bytes());
        CkmSp800108KdfParams kdf = Sp800108(AesTemplate(), AesTemplate());

        KeyStrengthRequest request = RefusedRequest(
            () => session.DeriveKey(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdf), StrongAes, AesTemplate()));

        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(1, fake.DeriveCalls);
        Assert.Equal([Created, SiblingA, SiblingB], fake.Destroyed);
        // The destroyed siblings' handles are gone from the parameters: Pkcs11Key.Derive cannot wrap them.
        Assert.Empty(kdf.RawAdditionalDerivedKeyHandles);
    }

    [Fact]
    public void Sp800108_AllowedSiblings_AreKept()
    {
        using CreationFake fake = Sp800108Fake(siblingBLength: 32);
        using var session = fake.CreateSession(policy: Only32Bytes());
        CkmSp800108KdfParams kdf = Sp800108(AesTemplate(), AesTemplate());

        ObjectHandle key = session.DeriveKey(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdf), StrongAes, AesTemplate());

        Assert.Equal(Created, key.ObjectId);
        Assert.Empty(fake.Destroyed);
        Assert.Equal([SiblingA, SiblingB], kdf.RawAdditionalDerivedKeyHandles);
        // The base key, the main key and both siblings: two reads (four calls) each.
        Assert.Equal(16, fake.GetAttributeValueCalls);
    }

    // A slot the token left at CK_INVALID_HANDLE is no key: skipped, while the others are still judged.
    [Fact]
    public void Sp800108_UnwrittenSiblingSlot_IsSkipped()
    {
        using CreationFake fake = Sp800108Fake(siblingBLength: 32);
        fake.SiblingHandles = [CK.CK_INVALID_HANDLE, SiblingB];
        using var session = fake.CreateSession(policy: Only32Bytes());
        CkmSp800108KdfParams kdf = Sp800108(AesTemplate(), AesTemplate());

        session.DeriveKey(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdf), StrongAes, AesTemplate());

        Assert.Empty(fake.Destroyed);
        Assert.Equal(12, fake.GetAttributeValueCalls);
    }

    [Fact]
    public void Sp800108_SiblingTemplateWith16Bytes_IsRefused_BeforeTheToken()
    {
        using CreationFake fake = Sp800108Fake(siblingBLength: 32);
        using var session = fake.CreateSession(policy: Only32Bytes());
        CkmSp800108KdfParams kdf = Sp800108(AesTemplate(32), AesTemplate(16));

        KeyStrengthRequest request = RefusedRequest(
            () => session.DeriveKey(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdf), StrongAes, AesTemplate()));

        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(0, fake.DeriveCalls);
        Assert.Empty(fake.Destroyed);
    }

    [Fact]
    public void Sp800108_UnderRecommended_ReadsNothing()
    {
        using CreationFake fake = Sp800108Fake(siblingBLength: 16);
        using var session = fake.CreateSession();
        CkmSp800108KdfParams kdf = Sp800108(AesTemplate(), AesTemplate());

        session.DeriveKey(new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdf), StrongAes, AesTemplate());

        Assert.Equal(0, fake.GetAttributeValueCalls);
        Assert.Empty(fake.Destroyed);
        Assert.Equal([SiblingA, SiblingB], kdf.RawAdditionalDerivedKeyHandles);
    }

    [Fact]
    public void CreateObject_AesValueOf16Bytes_IsRefused_BeforeTheToken()
    {
        using var fake = new CreationFake();
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Value(new byte[16]).Build();

        KeyStrengthRequest request = RefusedRequest(() => session.CreateObject([.. tpl.Attributes]));

        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(0, fake.CreateObjectCalls);
    }

    [Fact]
    public void CreateObject_AesValueOf32Bytes_IsCheckedAfterCreation_AndReturned()
    {
        using var fake = new CreationFake();
        fake.SetAes(Created, 32);
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Value(new byte[32]).Build();

        ObjectHandle key = session.CreateObject([.. tpl.Attributes]);

        Assert.Equal(Created, key.ObjectId);
        Assert.Equal(1, fake.CreateObjectCalls);
        Assert.Equal(4, fake.GetAttributeValueCalls);
        Assert.Empty(fake.Destroyed);
    }

    // A certificate or data object is no key: it has no strength to judge, and is not read.
    [Fact]
    public void CreateObject_NonKeyObject_IsNotJudged()
    {
        using var fake = new CreationFake();
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var tpl = ObjectTemplate.ForData().Value([0x01, 0x02]).Build();

        ObjectHandle created = session.CreateObject([.. tpl.Attributes]);

        Assert.Equal(Created, created.ObjectId);
        Assert.Equal(0, fake.GetAttributeValueCalls);
        Assert.Empty(fake.Destroyed);
    }

    // Any key class among the template's CKA_CLASS entries makes it a key: a CKO_DATA first cannot hide it (F5).
    [Fact]
    public void CreateObject_DataClassThenSecretKeyClass_IsJudgedAsAKey()
    {
        using var fake = new CreationFake();
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var dataClass = new ObjectAttribute(CKA.CKA_CLASS, (ulong)CKO.CKO_DATA);
        using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, (ulong)CKO.CKO_SECRET_KEY);
        using var keyType = new ObjectAttribute(CKA.CKA_KEY_TYPE, (ulong)CKK.CKK_AES);
        using var value = new ObjectAttribute(CKA.CKA_VALUE, new byte[16]);

        KeyStrengthRequest request = RefusedRequest(() => session.CreateObject([dataClass, keyClass, keyType, value]));

        Assert.Equal(KeyStrengthSource.Template, request.Source);
        Assert.Equal(16, request.ValueLengthBytes);
        Assert.Equal(0, fake.CreateObjectCalls);
    }

    // The SoftHSM2 case: the unwrapped key reports CKA_VALUE_LEN = 0. It is refused as unreported, not as
    // "AES-0", and destroyed (F3).
    [Fact]
    public void Unwrap_CreatedKeyWithZeroLength_IsRefusedAsUnreported_AndDestroyed()
    {
        using var fake = new CreationFake();
        fake.SetAes(StrongAes.ObjectId, 32);
        fake.SetAes(Created, 0);
        using var session = fake.CreateSession(policy: CryptoPolicy.Cnsa20);

        CryptoPolicyViolationException ex = Refusal(() => Unwrap(session));

        KeyStrengthRequest request = Assert.IsType<KeyStrengthRequest>(ex.Request);
        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Null(request.ValueLengthBytes);
        Assert.Contains("did not report", ex.Reason, StringComparison.Ordinal);
        Assert.Contains("so CNSA 2.0 compliance can't be verified", ex.Reason, StringComparison.Ordinal);
        Assert.Equal([Created], fake.Destroyed);
    }

    // A template stating CKA_VALUE_LEN = 0 names no length either: refused before the token, as unreported (F3).
    [Fact]
    public void GenerateAes_TemplateWithZeroLength_IsRefusedAsUnreported_BeforeTheToken()
    {
        using var fake = new CreationFake();
        using var session = fake.CreateSession(policy: CryptoPolicy.Cnsa20);

        CryptoPolicyViolationException ex = Refusal(() => GenerateAes(session, 0));

        Assert.Null(Assert.IsType<KeyStrengthRequest>(ex.Request).ValueLengthBytes);
        Assert.Contains("did not report", ex.Reason, StringComparison.Ordinal);
        Assert.Equal(0, fake.GenerateKeyCalls);
    }

    // A device error while reading back a created key is the token's error, and the key is still destroyed (F6).
    [Fact]
    public void CreatedKeyReadFails_WithDeviceError_Propagates_AndDestroysTheKey()
    {
        using var fake = new CreationFake();
        fake.SetAes(Created, 32);
        fake.ReadFailures[Created] = CKR.CKR_DEVICE_ERROR;
        using var session = fake.CreateSession(policy: StrongKeysOnly());

        Pkcs11Exception ex = Assert.ThrowsAny<Pkcs11Exception>(() => GenerateAes(session));

        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        Assert.Equal(1, fake.GenerateKeyCalls);
        Assert.Equal([Created], fake.Destroyed);
    }

    // The same for both halves of a pair: the read of one fails, both are destroyed.
    [Fact]
    public void KeyPairReadFails_WithDeviceError_Propagates_AndDestroysBothHalves()
    {
        using var fake = new CreationFake();
        fake.SetPq(CreatedPublic, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_1024);
        fake.SetPq(CreatedPrivate, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_1024);
        fake.ReadFailures[CreatedPrivate] = CKR.CKR_DEVICE_ERROR;
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM).Build();

        Pkcs11Exception ex = Assert.ThrowsAny<Pkcs11Exception>(() => session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), [.. pub.Attributes], [.. priv.Attributes], out _, out _));

        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        Assert.Equal([CreatedPublic, CreatedPrivate], fake.Destroyed);
    }

    [Fact]
    public void CopyObject_IsNotJudged()
    {
        using var fake = new CreationFake();
        fake.SetAes(WeakAes.ObjectId, 16);
        fake.SetAes(Created, 16);
        using var session = fake.CreateSession(policy: StrongKeysOnly());
        using var label = new ObjectAttribute(CKA.CKA_LABEL, "copy");

        ObjectHandle copy = session.CopyObject(WeakAes, [label]);

        Assert.Equal(Created, copy.ObjectId);
        Assert.Equal(1, fake.CopyObjectCalls);
        Assert.Equal(0, fake.GetAttributeValueCalls);
        Assert.Empty(fake.Destroyed);
    }

    [Fact]
    public void CreatedKeyFails_AndDestroyFails_ReportsTheHandle()
    {
        using var fake = new CreationFake();
        fake.SetAes(Created, 16);
        fake.DestroyResult = CKR.CKR_FUNCTION_FAILED;
        var logger = new CapturingLogger();
        using var session = fake.CreateSession(loggerFactory: new CapturingLoggerFactory(logger), policy: StrongKeysOnly());

        CryptoPolicyViolationException ex = Refusal(() => GenerateAes(session));

        KeyStrengthRequest request = Assert.IsType<KeyStrengthRequest>(ex.Request);
        Assert.Equal(KeyStrengthSource.CreatedKey, request.Source);
        Assert.Equal("T", ex.PolicyName);
        Assert.StartsWith("Too weak.", ex.Reason);
        Assert.Contains("handle 42", ex.Reason);
        Assert.Contains("could not be destroyed", ex.Reason);
        Assert.Contains(nameof(CKR.CKR_FUNCTION_FAILED), ex.Reason);
        Assert.Equal([Created], fake.Destroyed);

        CapturingLogger.Entry entry = Assert.Single(logger.Entries, e => e.Level == LogLevel.Error);
        Assert.Contains("42", entry.Message);
        Assert.Contains("T", entry.Message);
    }

    // Both halves of a pair are attempted even when the first destroy fails, and each failure is named.
    [Fact]
    public void KeyPairFails_AndBothDestroysFail_ReportsBothHandles()
    {
        using var fake = new CreationFake();
        fake.SetPq(CreatedPublic, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_768);
        fake.SetPq(CreatedPrivate, CKK.CKK_ML_KEM, (ulong)CkpMlKem.CKP_ML_KEM_768);
        fake.DestroyResult = CKR.CKR_FUNCTION_FAILED;
        var logger = new CapturingLogger();
        using var session = fake.CreateSession(loggerFactory: new CapturingLoggerFactory(logger), policy: StrongKeysOnly());
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM).Build();

        CryptoPolicyViolationException ex = Refusal(() => session.GenerateKeyPair(
            new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), [.. pub.Attributes], [.. priv.Attributes], out _, out _));

        Assert.Contains("handle 43", ex.Reason);
        Assert.Contains("handle 44", ex.Reason);
        Assert.Equal([CreatedPublic, CreatedPrivate], fake.Destroyed);
        Assert.Equal(2, logger.Entries.Count(e => e.Level == LogLevel.Error));
    }

    [Fact]
    public void Recommended_DoesNoPostCheckReads()
    {
        using var fake = new CreationFake();
        fake.SetAes(Created, 16);
        using var session = fake.CreateSession();

        ObjectHandle key = GenerateAes(session);

        Assert.Equal(Created, key.ObjectId);
        Assert.Equal(0, fake.GetAttributeValueCalls);
        Assert.Empty(fake.Destroyed);
    }

    [Fact]
    public void Recommended_DoesNoReadsOnAnyCreatingPath()
    {
        using var fake = new CreationFake();
        fake.SetAes(Created, 16);
        using var session = fake.CreateSession();
        using var pub = ObjectTemplate.ForPublicKey(CKK.CKK_ML_KEM).Build();
        using var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_ML_KEM).Build();
        using var value = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Value(new byte[16]).Build();

        Unwrap(session);
        session.GenerateKeyPair(new Mechanism(CKM.CKM_ML_KEM_KEY_PAIR_GEN), [.. pub.Attributes], [.. priv.Attributes], out _, out _);
        session.CreateObject([.. value.Attributes]);
        session.UnwrapKeyAuthenticated(
            new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 128)), StrongAes, new byte[48], [0x01], AesTemplate());

        Assert.Equal(0, fake.GetAttributeValueCalls);
        Assert.Empty(fake.Destroyed);
    }
}
