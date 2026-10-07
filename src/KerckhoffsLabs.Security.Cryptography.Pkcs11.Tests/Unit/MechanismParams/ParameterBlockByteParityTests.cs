using System.Reflection;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// The bytes a mechanism's parameter block puts in native memory must not change when the boxed
/// <see cref="object"/> path (<c>UnmanagedMemory.SizeOf(Type)</c> plus <c>UnmanagedMemory.Write(object)</c>)
/// is replaced by the typed one (<c>Pkcs11Marshal.SizeOf&lt;T&gt;</c> plus <c>Pkcs11Marshal.WriteStructure&lt;T&gt;</c>).
/// This compares the two for every parameter type, on the platform it runs on: Pack=1 on Windows, where
/// both go through the generated <c>_Windows</c> sibling, and natural alignment elsewhere.
/// </summary>
public sealed unsafe class ParameterBlockByteParityTests
{
    private static readonly Dictionary<string, Func<ParameterKeys, MechanismParameters>> Cases = new(StringComparer.Ordinal)
    {
        [nameof(CkmAesCcmParams)] = _ => new CkmAesCcmParams(dataLen: 64, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77], [0xAA, 0xBB, 0xCC], macLen: 16),
        [nameof(CkmAesGcmParams)] = _ => new CkmAesGcmParams([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], [0xA0, 0xA1], tagBits: 128),
        [nameof(CkmCcmMessageParams)] = _ => CkmCcmMessageParams.ForDecrypt(dataLen: 48, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99], new byte[12]),
        [nameof(CkmChaCha20Params)] = _ => new CkmChaCha20Params([0x01, 0x00, 0x00, 0x00], blockCounterBits: 32, new byte[12], nonceBits: 96),
        [nameof(CkmEcdh1DeriveParams)] = _ => new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, [0x04, 0x01, 0x02, 0x03, 0x04, 0x05], [0x77, 0x78, 0x79]),
        [nameof(CkmEddsaParams)] = _ => new CkmEddsaParams(phFlag: true, [0xAA, 0xBB, 0xCC]),
        [nameof(CkmGcmMessageParams)] = _ => CkmGcmMessageParams.ForDecrypt([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], new byte[13]),
        [nameof(CkmHashPqcSignParams)] = _ => new CkmHashPqcSignParams(CKM.CKM_SHA256, CkhHedge.CKH_HEDGE_REQUIRED, [0x01, 0x02]),
        [nameof(CkmHkdfParams)] = keys => CkmHkdfParams.WithSaltKey(HkdfOperation.ExtractOnly, CKM.CKM_SHA384_HMAC, keys.Secret(9), [0x1F, 0x2F]),
        [nameof(CkmIke1ExtendedDeriveParams)] = keys => new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, keygxy: keys.Secret(5), [0xE1, 0xE2]),
        [nameof(CkmIke1PrfDeriveParams)] = keys => new CkmIke1PrfDeriveParams(
            CKM.CKM_SHA256_HMAC, keygxy: keys.Secret(11), prevKey: keys.Secret(22), [0x01, 0x02, 0x03, 0x04], [0x05, 0x06, 0x07, 0x08], keyNumber: 3),
        [nameof(CkmIke2PrfPlusDeriveParams)] = keys => new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, seedKey: keys.Secret(7), [0x5E, 0x5D, 0x5C]),
        [nameof(CkmIkePrfDeriveParams)] = keys => new CkmIkePrfDeriveParams(
            CKM.CKM_SHA256_HMAC, dataAsKey: true, rekey: true, [0x21, 0x22, 0x23], [0x31, 0x32, 0x33, 0x34], newKey: keys.Secret(42)),
        [nameof(CkmPkcs5Pbkd2Params)] = _ => new CkmPkcs5Pbkd2Params(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, "pw"u8),
        [nameof(CkmPqcSignParams)] = _ => new CkmPqcSignParams(CkhHedge.CKH_HEDGE_REQUIRED, [0xC0, 0xC1, 0xC2]),
        [nameof(CkmRc2CbcParams)] = _ => new CkmRc2CbcParams(128, [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]),
        [nameof(CkmRc2Params)] = _ => new CkmRc2Params(128),
        [nameof(CkmRsaPkcsOaepParams)] = _ => new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, [0x0A, 0x0B]),
        [nameof(CkmRsaPkcsPssParams)] = _ => new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32),
        [nameof(CkmSalsa20ChaCha20Poly1305MsgParams)] = _ => CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(new byte[12], new byte[16]),
        [nameof(CkmSalsa20ChaCha20Poly1305Params)] = _ => new CkmSalsa20ChaCha20Poly1305Params(new byte[12], [0x91, 0x92]),
        [nameof(CkmSalsa20Params)] = _ => new CkmSalsa20Params([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], new byte[8], nonceBits: 64),
        [nameof(CkmSp800108KdfParams)] = keys => CkmSp800108KdfParams.Feedback(CKM.CKM_SHA384_HMAC)
            .IterationCounter(widthInBits: 16, littleEndian: true)
            .ByteArray([0x66, 0x62, 0x6B])
            .Key(keys.Secret(0xABCD))
            .WithIV([0xD1, 0xD2, 0xD3, 0xD4])
            .Build(),
        [nameof(CkmX2RatchetInitializeParams)] = keys => new CkmX2RatchetInitializeParams(
            [0x51, 0x52, 0x53, 0x54], peerPublicPrekey: keys.PublicOnly(1), peerPublicIdentity: keys.PublicOnly(2), ownPublicIdentity: keys.Pair(0x30, 3),
            encryptedHeader: true, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: CKM.CKM_SHA256_HMAC),
        [nameof(CkmX2RatchetRespondParams)] = keys => new CkmX2RatchetRespondParams(
            [0x61, 0x62, 0x63, 0x64], ownPrekey: keys.Pair(1, 0x10), initiatorIdentity: keys.PublicOnly(2), ownPublicIdentity: keys.Pair(0x30, 3),
            encryptedHeader: false, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: CKM.CKM_SHA384_HMAC),
        [nameof(CkmX3dhInitiateParams)] = keys => new CkmX3dhInitiateParams(
            kdf: CKM.CKM_SHA256_HMAC, peerIdentity: keys.Pair(0x20, 2), peerPrekey: keys.Pair(0x30, 3), [0x51, 0x52, 0x53], [0x61, 0x62],
            ownIdentity: keys.Pair(4, 0x40), ownEphemeral: keys.Pair(5, 0x50)),
        [nameof(CkmX3dhRespondParams)] = keys => new CkmX3dhRespondParams(
            kdf: CKM.CKM_SHA384_HMAC, [0x71, 0x72], [0x81, 0x82, 0x83], [0x91, 0x92], initiatorIdentity: keys.Pair(0x70, 7), [0xA1, 0xA2, 0xA3]),
        [nameof(CkmXeddsaParams)] = _ => new CkmXeddsaParams(CKM.CKM_SHA512),
    };

    public static TheoryData<string> ParameterTypes => [.. Cases.Keys.Order(StringComparer.Ordinal)];

    [Theory]
    [MemberData(nameof(ParameterTypes))]
    public void TypedWrite_PutsTheSameBytesInNativeMemoryAsTheObjectPath(string parameterType)
    {
        using var keys = new ParameterKeys();
        MechanismParameters parameters = Cases[parameterType](keys);
        using var scope = keys.NewScope();
        object lowLevel = parameters.BuildMarshalable(scope);

        byte[] objectPath = WriteThroughObjectPath(lowLevel);
        byte[] typedPath = (byte[])TypedWrite.MakeGenericMethod(lowLevel.GetType()).Invoke(null, [lowLevel])!;

        Assert.Equal(objectPath, typedPath);
    }

    // Every parameter type the library ships gets a case: a new one that bypassed this check would be
    // switched over unverified.
    [Fact]
    public void EveryParameterType_HasACase()
    {
        string[] shipped = [.. typeof(MechanismParameters).Assembly.GetTypes()
            .Where(t => !t.IsAbstract && t.IsSubclassOf(typeof(MechanismParameters)) && !t.IsSubclassOf(typeof(VendorMechanismParameters)))
            .Select(t => t.Name)
            .Order(StringComparer.Ordinal)];

        Assert.Equal(shipped, Cases.Keys.Order(StringComparer.Ordinal));
    }

    // Both paths write into zeroed memory: neither writes a struct's padding, so uninitialized bytes
    // there would make the comparison depend on what the allocator left behind.
    private static byte[] WriteThroughObjectPath(object structure)
    {
        int size = UnmanagedMemory.SizeOf(structure.GetType());
        IntPtr block = (IntPtr)NativeMemory.AllocZeroed((nuint)size);
        try
        {
            UnmanagedMemory.Write(block, structure);
            return new ReadOnlySpan<byte>((void*)block, size).ToArray();
        }
        finally
        {
            NativeMemory.Free((void*)block);
        }
    }

    private static readonly MethodInfo TypedWrite =
        typeof(ParameterBlockByteParityTests).GetMethod(nameof(WriteThroughTypedPath), BindingFlags.NonPublic | BindingFlags.Static)!;

    private static byte[] WriteThroughTypedPath<T>(object structure) where T : unmanaged
    {
        T value = (T)structure;
        int size = Pkcs11Marshal.SizeOf<T>();
        IntPtr block = (IntPtr)NativeMemory.AllocZeroed((nuint)size);
        try
        {
            Pkcs11Marshal.WriteStructure(block, in value);
            return new ReadOnlySpan<byte>((void*)block, size).ToArray();
        }
        finally
        {
            NativeMemory.Free((void*)block);
        }
    }
}
