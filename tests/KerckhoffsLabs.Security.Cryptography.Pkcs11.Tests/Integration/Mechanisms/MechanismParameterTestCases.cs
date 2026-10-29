using System.Buffers.Binary;
using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>
/// A mechanism parameter outside what PKCS#11 v3.2 allows is refused at the <c>C_*Init</c> that receives it,
/// checked on every real backend: the AES-GCM and AES-CCM parameter blocks with a NULL pointer behind a length
/// or a length out of its range, AES-CTR's counter width and the overflow of its counter, and the output length of
/// the general-length MACs.
/// </summary>
/// <remarks>
/// <para>
/// The library's parameter types refuse these values before any native call, so each case lays the
/// <c>CK_*_PARAMS</c> struct out itself, with pointers into unmanaged memory it owns, and passes it as a raw
/// block through the raw dispatch: the refusal is the module's. A module must not read through a NULL
/// pointer it was given a length for, so a crash is a finding, not a skip.
/// </para>
/// <para>
/// Every refused Init is followed, in the same session, by an Init with good parameters whose result is
/// checked against the BCL: the refusal started no operation (§5.2) and left nothing behind.
/// </para>
/// </remarks>
internal static class MechanismParameterTestCases
{
    private static readonly byte[] Message = "the quick brown fox jumps over the lazy dog"u8.ToArray();
    private static readonly byte[] Aad = "header.v1"u8.ToArray();

    private delegate CKR KeyedInit(NativeCULong session, in CK_MECHANISM mechanism, NativeCULong key);

    private static void AssertOk(CKR rv, string step) =>
        Assert.True(rv == CKR.CKR_OK, $"{step} was expected to succeed but returned {rv}.");

    private static void WithSession(IPkcs11Backend backend, Action<LowLevelPkcs11Library, NativeCULong, Pkcs11SessionCore> body)
    {
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            body(backend.Library.LowLevelLibrary!, (NativeCULong)session.SessionId, session);
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    private static CKR Init(KeyedInit init, NativeCULong sid, Mechanism mechanism, ObjectHandle key)
    {
        using var scope = new MechanismParameterScope();
        CK_MECHANISM mech = mechanism.Marshal(scope, out _);
        return init(sid, in mech, (NativeCULong)key.ObjectId);
    }

    // === AES-GCM and AES-CCM ================================================

    public static TheoryData<string> AeadParameterFaults =>
    [
        "GCM pIv NULL", "GCM ulIvLen 0", "GCM pAAD NULL", "GCM ulTagBits 136",
        "CCM pNonce NULL", "CCM ulNonceLen 6", "CCM ulNonceLen 14", "CCM pAAD NULL",
        "CCM ulMACLen 2", "CCM ulMACLen 5", "CCM ulMACLen 18",
    ];

    // PKCS#11 v3.2 §6.13.7: CK_GCM_PARAMS takes an IV of 1 to 2^32 - 1 bytes and a tag of 0 to 128 bits;
    // CK_CCM_PARAMS a nonce of 7 to 13 bytes and a MAC of 4, 6, 8, 10, 12, 14 or 16 bytes; and §6.13.2, §6.13.4
    // let pAAD be NULL only when ulAADLen is 0. C_EncryptInit and C_DecryptInit refuse a value outside that
    // with CKR_MECHANISM_PARAM_INVALID (§5.1.6: "invalid parameters were supplied to the mechanism"). A NULL
    // pointer behind a non-zero length may also be refused as CKR_ARGUMENTS_BAD, the code §5.1.6 gives for
    // arguments "in some way not appropriate"; nothing else is taken. After each refusal the same session runs
    // the Init again with good parameters, and its result is the BCL's.
    internal static void Assert_AeadParameter_OutOfRange_IsMechanismParamInvalid(IPkcs11Backend backend, string fault)
    {
        bool gcm = fault.StartsWith("GCM", StringComparison.Ordinal);
        CKM type = gcm ? CKM.CKM_AES_GCM : CKM.CKM_AES_CCM;
        backend.RequireMechanismFlags(type, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");
        bool nullPointer = fault.EndsWith("NULL", StringComparison.Ordinal);
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                using var buffers = new NativeBuffers();
                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                Mechanism bad = gcm ? Gcm(lowLevel, buffers, nonce, fault) : Ccm(buffers, nonce, fault);
                Mechanism good = gcm ? Gcm(lowLevel, buffers, nonce, fault: null) : Ccm(buffers, nonce, fault: null);
                byte[] expected = new byte[Message.Length + 16];
                if (gcm)
                {
                    using var bcl = new AesGcm(rawKey, 16);
                    bcl.Encrypt(nonce, Message, expected.AsSpan(0, Message.Length), expected.AsSpan(Message.Length), Aad);
                }
                else
                {
                    using var bcl = new AesCcm(rawKey);
                    bcl.Encrypt(nonce, Message, expected.AsSpan(0, Message.Length), expected.AsSpan(Message.Length), Aad);
                }

                foreach (bool encrypt in (bool[])[true, false])
                {
                    string op = encrypt ? "C_EncryptInit" : "C_DecryptInit";
                    KeyedInit init = encrypt ? lowLevel.C_EncryptInit : lowLevel.C_DecryptInit;
                    CKR rv = Init(init, sid, bad, key);
                    Assert.True(rv == CKR.CKR_MECHANISM_PARAM_INVALID || (nullPointer && rv == CKR.CKR_ARGUMENTS_BAD),
                        $"{op}({type}) with {fault} returned {rv}.");

                    AssertOk(Init(init, sid, good, key), $"{op}({type}) with good parameters after the refusal");
                    byte[] input = encrypt ? Message : expected;
                    byte[] output = new byte[expected.Length];
                    rv = encrypt
                        ? lowLevel.C_Encrypt(sid, input, output, lengthOnly: false, out NativeCULong written)
                        : lowLevel.C_Decrypt(sid, input, output, lengthOnly: false, out written);
                    AssertOk(rv, encrypt ? "C_Encrypt" : "C_Decrypt");
                    Assert.Equal(encrypt ? expected : Message, output.AsSpan(0, (int)(ulong)written).ToArray());
                }
            }
            finally { session.DestroyObject(key); }
        });
    }

    // A CK_GCM_PARAMS with a 12-byte IV, the AAD and a 128-bit tag, but for the fault. ulIvBits is the IV length
    // in bits for a module bound through a v3.x interface and 0 otherwise, as the library sends it.
    private static Mechanism Gcm(LowLevelPkcs11Library lowLevel, NativeBuffers buffers, byte[] iv, string? fault)
    {
        ulong ivLen = fault == "GCM ulIvLen 0" ? 0UL : (ulong)iv.Length;
        var parameter = new CK_GCM_PARAMS
        {
            Iv = fault == "GCM pIv NULL" ? IntPtr.Zero : buffers.Of(iv),
            IvLen = (NativeCULong)ivLen,
            IvBits = (NativeCULong)(lowLevel.IsBoundThroughV3Interface ? ivLen * 8 : 0UL),
            AAD = fault == "GCM pAAD NULL" ? IntPtr.Zero : buffers.Of(Aad),
            AADLen = (NativeCULong)(ulong)Aad.Length,
            TagBits = (NativeCULong)(fault == "GCM ulTagBits 136" ? 136UL : 128UL),
        };
        return RawParameter.From(CKM.CKM_AES_GCM, in parameter);
    }

    // A CK_CCM_PARAMS for the message, with a 12-byte nonce, the AAD and a 16-byte MAC, but for the fault. A nonce
    // of the wrong length is the first bytes of a longer one.
    private static Mechanism Ccm(NativeBuffers buffers, byte[] nonce, string? fault)
    {
        int nonceLen = fault switch { "CCM ulNonceLen 6" => 6, "CCM ulNonceLen 14" => 14, _ => nonce.Length };
        byte[] nonceBytes = [.. nonce, .. RandomNumberGenerator.GetBytes(2)];
        var parameter = new CK_CCM_PARAMS
        {
            DataLen = (NativeCULong)(ulong)Message.Length,
            Nonce = fault == "CCM pNonce NULL" ? IntPtr.Zero : buffers.Of(nonceBytes[..nonceLen]),
            NonceLen = (NativeCULong)(ulong)nonceLen,
            AAD = fault == "CCM pAAD NULL" ? IntPtr.Zero : buffers.Of(Aad),
            AADLen = (NativeCULong)(ulong)Aad.Length,
            MACLen = (NativeCULong)(fault switch { "CCM ulMACLen 2" => 2UL, "CCM ulMACLen 5" => 5UL, "CCM ulMACLen 18" => 18UL, _ => 16UL }),
        };
        return RawParameter.From(CKM.CKM_AES_CCM, in parameter);
    }

    // === AES-CTR ============================================================

    // A CK_AES_CTR_PARAMS: ulCounterBits, then the 16-byte counter block.
    private static Mechanism Ctr(ulong counterBits, byte[] counterBlock)
    {
        byte[] parameter = new byte[UnmanagedMemory.NativeULongSize + 16];
        if (UnmanagedMemory.NativeULongSize == 8)
            BinaryPrimitives.WriteUInt64LittleEndian(parameter, counterBits);
        else
            BinaryPrimitives.WriteUInt32LittleEndian(parameter, checked((uint)counterBits));
        counterBlock.CopyTo(parameter, parameter.Length - 16);
#pragma warning disable KLPKCS11009 // CKM_AES_CTR through the raw dispatch, which the policy does not see.
        return new Mechanism(CKM.CKM_AES_CTR, parameter);
#pragma warning restore KLPKCS11009
    }

    // AES-CTR over the whole counter block as a 128-bit big-endian counter, from the BCL's AES-ECB.
    private static byte[] AesCtr(byte[] key, byte[] initialCounter, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] counter = (byte[])initialCounter.Clone();
        byte[] output = new byte[data.Length];
        for (int offset = 0; offset < data.Length; offset += 16)
        {
            byte[] keystream = aes.EncryptEcb(counter, PaddingMode.None);
            for (int i = 0; i < 16 && offset + i < data.Length; i++)
                output[offset + i] = (byte)(data[offset + i] ^ keystream[i]);
            int carry = 15;
            while (carry >= 0 && unchecked(++counter[carry]) == 0)
                carry--;
        }
        return output;
    }

    public static TheoryData<ulong> AesCtrCounterBitsOutOfRange => [0UL, 129UL];

    // PKCS#11 v3.2 §6.11.2: ulCounterBits "shall be such that 0 < ulCounterBits ≤ 128. For any values outside
    // this range the mechanism shall return CKR_MECHANISM_PARAM_INVALID", at C_EncryptInit and C_DecryptInit
    // alike. After each refusal the same session runs the Init with a 128-bit counter, and its result is the
    // BCL's.
    internal static void Assert_AesCtr_CounterBitsOutOfRange_IsMechanismParamInvalid(IPkcs11Backend backend, ulong counterBits)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_CTR, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                byte[] counter = RandomNumberGenerator.GetBytes(16);
                byte[] expected = AesCtr(rawKey, counter, Message);
                foreach (bool encrypt in (bool[])[true, false])
                {
                    string op = encrypt ? "C_EncryptInit" : "C_DecryptInit";
                    KeyedInit init = encrypt ? lowLevel.C_EncryptInit : lowLevel.C_DecryptInit;
                    CKR rv = Init(init, sid, Ctr(counterBits, counter), key);
                    Assert.True(rv == CKR.CKR_MECHANISM_PARAM_INVALID, $"{op}(CKM_AES_CTR) with ulCounterBits {counterBits} returned {rv}.");

                    AssertOk(Init(init, sid, Ctr(128, counter), key), $"{op}(CKM_AES_CTR) with a 128-bit counter after the refusal");
                    byte[] input = encrypt ? Message : expected;
                    byte[] output = new byte[input.Length];
                    rv = encrypt
                        ? lowLevel.C_Encrypt(sid, input, output, lengthOnly: false, out NativeCULong written)
                        : lowLevel.C_Decrypt(sid, input, output, lengthOnly: false, out written);
                    AssertOk(rv, encrypt ? "C_Encrypt" : "C_Decrypt");
                    Assert.Equal(encrypt ? expected : Message, output.AsSpan(0, (int)(ulong)written).ToArray());
                }
            }
            finally { session.DestroyObject(key); }
        });
    }

    // PKCS#11 v3.2 §6.11.3: "If an attempt to encrypt/decrypt is made which will cause an overflow of the counter
    // block's counter bits, then the mechanism shall return CKR_DATA_LEN_RANGE", and its example is the one here:
    // with ulCounterBits = 2 and the counter bits starting at 1, "only 3 blocks of data can be processed". Three
    // blocks encrypt to the BCL's CTR (the counter takes 1, 2 and 3, so it never carries); a fourth is refused,
    // rather than wrapping the counter (which reuses keystream) or carrying into the nonce, and the refusal ends
    // the operation (§5.2), so the next C_EncryptInit succeeds.
    internal static void Assert_AesCtr_CounterOverflow_IsDataLenRange(IPkcs11Backend backend)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_CTR, f => f.Encrypt, "CKF_ENCRYPT");
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                byte[] counter = RandomNumberGenerator.GetBytes(16);
                counter[15] = (byte)((counter[15] & 0xFC) | 0x01);
                byte[] threeBlocks = RandomNumberGenerator.GetBytes(48);
                byte[] fourBlocks = RandomNumberGenerator.GetBytes(64);

                AssertOk(Init(lowLevel.C_EncryptInit, sid, Ctr(2, counter), key), "C_EncryptInit(CKM_AES_CTR) with a 2-bit counter");
                byte[] output = new byte[64];
                AssertOk(lowLevel.C_Encrypt(sid, threeBlocks, output, lengthOnly: false, out NativeCULong written), "C_Encrypt of three blocks");
                Assert.Equal(AesCtr(rawKey, counter, threeBlocks), output.AsSpan(0, (int)(ulong)written).ToArray());

                AssertOk(Init(lowLevel.C_EncryptInit, sid, Ctr(2, counter), key), "C_EncryptInit(CKM_AES_CTR) with a 2-bit counter");
                CKR rv = lowLevel.C_Encrypt(sid, fourBlocks, output, lengthOnly: false, out _);
                Assert.True(rv == CKR.CKR_DATA_LEN_RANGE, $"C_Encrypt of four blocks under a 2-bit counter starting at 1 returned {rv}.");

                AssertOk(Init(lowLevel.C_EncryptInit, sid, Ctr(128, counter), key), "C_EncryptInit(CKM_AES_CTR) after the refusal");
                AssertOk(lowLevel.C_Encrypt(sid, fourBlocks, output, lengthOnly: false, out written), "C_Encrypt of four blocks under a 128-bit counter");
                Assert.Equal(AesCtr(rawKey, counter, fourBlocks), output.AsSpan(0, (int)(ulong)written).ToArray());
            }
            finally { session.DestroyObject(key); }
        });
    }

    // === General-length MACs ================================================

    // RFC 4493 §4's AES-128 key and 64-byte message, whose CMAC is 51f0bebf7e3b9d92fc49741779363cfe.
    private static readonly byte[] CmacKey = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
    private static readonly byte[] CmacMessage = Convert.FromHexString(
        "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710");
    private static readonly byte[] CmacOfTheMessage = Convert.FromHexString("51f0bebf7e3b9d92fc49741779363cfe");

    public static TheoryData<string> MacGeneralLengthsOutOfRange =>
        ["HMAC-SHA256 33", "HMAC-SHA256 2^32 + 16", "CMAC 17", "CMAC 2^32 + 8"];

    // A CK_MAC_GENERAL_PARAMS: the MAC length, a CK_ULONG.
    private static Mechanism MacGeneral(CKM type, ulong length)
    {
        byte[] parameter = new byte[UnmanagedMemory.NativeULongSize];
        if (parameter.Length == 8)
            BinaryPrimitives.WriteUInt64LittleEndian(parameter, length);
        else
            BinaryPrimitives.WriteUInt32LittleEndian(parameter, checked((uint)length));
        return new Mechanism(type, parameter);
    }

    // The general-length MACs take a CK_MAC_GENERAL_PARAMS holding the output length: 1 to 32 bytes for
    // CKM_SHA256_HMAC_GENERAL (PKCS#11 v3.2 §6.22.3) and 1 to the block size for CKM_AES_CMAC_GENERAL (§6.14.3,
    // Table 121). A length outside that is an invalid parameter, and C_SignInit refuses it with
    // CKR_MECHANISM_PARAM_INVALID (§5.1.6). The rows above 2^32, where CK_ULONG is 64 bits, catch a module that
    // narrows the length to 32 bits and signs 16 (8) bytes. After the refusal the same session signs with a length
    // in range, and the MAC is the start of the full one (the BCL's HMAC-SHA256; RFC 4493's CMAC).
    internal static void Assert_MacGeneral_LengthOutOfRange_IsMechanismParamInvalid(IPkcs11Backend backend, string row)
    {
        bool hmac = row.StartsWith("HMAC", StringComparison.Ordinal);
        if (row.Contains("2^32", StringComparison.Ordinal))
            Assert.SkipUnless(UnmanagedMemory.NativeULongSize == 8, "CK_ULONG is 32 bits on this platform.");
        CKM type = hmac ? CKM.CKM_SHA256_HMAC_GENERAL : CKM.CKM_AES_CMAC_GENERAL;
        backend.RequireMechanismFlags(type, f => f.Sign, "CKF_SIGN");
        ulong length = row switch
        {
            "HMAC-SHA256 33" => 33,
            "HMAC-SHA256 2^32 + 16" => (1UL << 32) + 16,
            "CMAC 17" => 17,
            _ => (1UL << 32) + 8,
        };
        int inRange = hmac ? 16 : 8;
        WithSession(backend, (lowLevel, sid, session) =>
        {
            byte[] rawKey = hmac ? RandomNumberGenerator.GetBytes(32) : CmacKey;
            byte[] message = hmac ? Message : CmacMessage;
            ObjectHandle key = CreateSigningKey(session, hmac ? CKK.CKK_GENERIC_SECRET : CKK.CKK_AES, rawKey);
            try
            {
                CKR rv = Init(lowLevel.C_SignInit, sid, MacGeneral(type, length), key);
                Assert.True(rv == CKR.CKR_MECHANISM_PARAM_INVALID, $"C_SignInit({type}) with a MAC length of {length} returned {rv}.");

                AssertOk(Init(lowLevel.C_SignInit, sid, MacGeneral(type, (ulong)inRange), key), $"C_SignInit({type}) with a MAC length of {inRange} after the refusal");
                byte[] mac = new byte[64];
                AssertOk(lowLevel.C_Sign(sid, message, mac, lengthOnly: false, out NativeCULong written), "C_Sign");
                byte[] full = hmac ? HMACSHA256.HashData(rawKey, message) : CmacOfTheMessage;
                Assert.Equal(full[..inRange], mac.AsSpan(0, (int)(ulong)written).ToArray());
            }
            finally { session.DestroyObject(key); }
        });
    }

    private static ObjectHandle CreateSigningKey(Pkcs11SessionCore session, CKK keyType, byte[] value)
    {
        using var keyClass = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
        using var type = new ObjectAttribute(CKA.CKA_KEY_TYPE, keyType);
        using var token = new ObjectAttribute(CKA.CKA_TOKEN, false);
        using var sign = new ObjectAttribute(CKA.CKA_SIGN, true);
        using var verify = new ObjectAttribute(CKA.CKA_VERIFY, true);
        using var attrValue = new ObjectAttribute(CKA.CKA_VALUE, value);
        return session.CreateObject([keyClass, type, token, sign, verify, attrValue]);
    }
}
