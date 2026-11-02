using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

#pragma warning disable KLPKCS11009 // CKM_AES_CTR runs under CryptoPolicy.NistApproved, which allows it

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

/// <summary>
/// <see cref="CkmAesCtrParams"/> on a real token: <c>CKM_AES_CTR</c> through the typed descriptor
/// and the policy-checked <c>Encrypt</c>/<c>Decrypt</c>, compared with a CTR built from the BCL's
/// AES-ECB (the BCL has no CTR mode) that increments only the low <c>counterBits</c> bits of the block,
/// big-endian. The cases never overflow the counter: what a token does at overflow
/// (<c>CKR_DATA_LEN_RANGE</c>, PKCS#11 v3.2 §6.11.3) is the raw-parameter test
/// <c>Assert_AesCtr_CounterOverflow_IsDataLenRange</c>'s to see.
/// </summary>
internal static class AesCtrParamsTestCases
{
    // counterBits, the low 16 bytes of the counter block as hex, message length in bytes. The block's
    // bytes above counterBits are a nonce the token must leave alone.
    public static TheoryData<int, string, int> Rows => new()
    {
        { 128, "000102030405060708090a0b0c0d0eff", 80 },   // carries out of the last byte
        { 128, "00000000000000007fffffffffffffff", 64 },   // carries across the 64-bit boundary
        { 128, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 37 },   // SP 800-38A's block, a partial last block
        { 32, "a1a2a3a4a5a6a7a8a9aaabacad0000fe", 80 },    // carries into the next byte inside the 32 bits
        { 64, "b1b2b3b4b5b6b7b8000000ffffffffff", 48 },    // carries across a 32-bit boundary inside 64 bits
        { 16, "c1c2c3c4c5c6c7c8c9cacbcccdce00ff", 33 },
        { 12, "d1d2d3d4d5d6d7d8d9dadbdcddde0aff", 48 },    // a width that is not a whole number of bytes
    };

    // The message uses the counter's last value (low 32 bits 0xFFFFFFFE, then 0xFFFFFFFF) without overflowing it.
    // PKCS#11 v3.2 §6.11.3 allows it; a module that refuses it is skipped on its answer, not bent around.
    public static TheoryData<int, string, int> RowsUsingTheLastCounterValue => new()
    {
        { 32, "a1a2a3a4a5a6a7a8a9aaabacfffffffe", 32 },
        { 128, "ffffffffffffffffffffffffffffffff", 16 },
    };

    internal static void Assert_Encrypt_MatchesTheBclCtr(IPkcs11Backend backend, int counterBits, string blockHex, int length)
    {
        backend.RequireMechanismFlags(CKM.CKM_AES_CTR, f => f.Encrypt && f.Decrypt, "CKF_ENCRYPT and CKF_DECRYPT");
        using var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            byte[] rawKey = RandomNumberGenerator.GetBytes(32);
            ObjectHandle key = TestKeys.CreateAes256Key(session, rawKey);
            try
            {
                byte[] block = Convert.FromHexString(blockHex);
                byte[] message = RandomNumberGenerator.GetBytes(length);
                byte[] expected = Ctr(rawKey, block, counterBits, message);
                var mechanism = new Mechanism(CKM.CKM_AES_CTR, new CkmAesCtrParams(counterBits, block));

                // CryptoPolicy.Recommended refuses unauthenticated CTR; NistApproved allows it (SP 800-38A).
                using var nist = session.UsePolicy(CryptoPolicy.NistApproved);
                Assert.Equal(expected, session.Encrypt(mechanism, key, message));
                Assert.Equal(message, session.Decrypt(mechanism, key, expected));
            }
            finally { session.DestroyObject(key); }
        }
        finally { TestKeys.LogoutIfRequired(backend, session); }
    }

    // CTR from AES-ECB: the counter block is an unsigned big-endian integer, and only its low counterBits
    // bits are incremented (modulo 2^counterBits), the rest being the nonce.
    internal static byte[] Ctr(byte[] key, byte[] initialBlock, int counterBits, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        UInt128 mask = counterBits == 128 ? UInt128.MaxValue : (UInt128.One << counterBits) - 1;
        UInt128 counter = System.Buffers.Binary.BinaryPrimitives.ReadUInt128BigEndian(initialBlock);
        byte[] output = new byte[data.Length];
        byte[] block = new byte[16];
        for (int offset = 0; offset < data.Length; offset += 16)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt128BigEndian(block, counter);
            byte[] keystream = aes.EncryptEcb(block, PaddingMode.None);
            for (int i = 0; i < 16 && offset + i < data.Length; i++)
                output[offset + i] = (byte)(data[offset + i] ^ keystream[i]);
            counter = unchecked((counter & ~mask) | ((counter + 1) & mask));
        }
        return output;
    }
}
