using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// These cases run ciphers and MACs outside the default policy (Camellia ECB, the AES feedback modes) on purpose,
// under a scoped AllowInsecure lease; the compile-time policy analyzer flags them, so its warnings are suppressed
// for this file only.
#pragma warning disable KLPKCS11008, KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Mechanisms;

// The AES feedback modes, ciphertext stealing and GMAC; Camellia; Poly1305.
internal static partial class MechanismCoverageTestCases
{
    private static readonly byte[] AesKey = [.. Enumerable.Range(0, 32).Select(i => (byte)(0x60 + i))];
    private static readonly byte[] Plaintext37 = "the quick brown fox jumps over the la"u8.ToArray();

    private static byte[] AesEcbBlock(byte[] key, ReadOnlySpan<byte> block)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptEcb(block, PaddingMode.None);
    }

    /// <summary>
    /// CFB with an s-bit segment (NIST SP 800-38A §6.3) for any s from 1 to 128, built bit by bit on AES-ECB: each
    /// segment is the plaintext XOR the leading s bits of the encrypted shift register, which then shifts the
    /// ciphertext segment in. A trailing partial segment uses as many bits as there are.
    /// </summary>
    internal static byte[] ReferenceCfb(byte[] key, byte[] iv, byte[] plaintext, int segmentBits)
    {
        UInt128 register = ToUInt128(iv);
        byte[] output = new byte[plaintext.Length];
        int totalBits = plaintext.Length * 8;
        for (int start = 0; start < totalBits; start += segmentBits)
        {
            UInt128 keystream = ToUInt128(AesEcbBlock(key, FromUInt128(register)));
            int bits = Math.Min(segmentBits, totalBits - start);
            UInt128 segment = 0;
            for (int i = 0; i < bits; i++)
            {
                int position = start + i;
                bool p = (plaintext[position / 8] & (0x80 >> (position % 8))) != 0;
                bool k = ((keystream >> (127 - i)) & 1) != 0;
                if (p ^ k)
                {
                    output[position / 8] |= (byte)(0x80 >> (position % 8));
                    segment |= (UInt128)1 << (bits - 1 - i);
                }
            }
            register = bits == 128 ? segment : (register << bits) | segment;
        }
        return output;
    }

    // OFB (NIST SP 800-38A §6.4): the plaintext XOR the chain of encryptions of the IV.
    internal static byte[] ReferenceOfb(byte[] key, byte[] iv, byte[] plaintext)
    {
        byte[] output = new byte[plaintext.Length];
        byte[] block = iv;
        for (int offset = 0; offset < plaintext.Length; offset += 16)
        {
            block = AesEcbBlock(key, block);
            for (int i = offset; i < Math.Min(offset + 16, plaintext.Length); i++)
                output[i] = (byte)(plaintext[i] ^ block[i - offset]);
        }
        return output;
    }

    /// <summary>
    /// CBC with ciphertext stealing (NIST SP 800-38A Addendum) in the variant given: CBC over the plaintext padded with
    /// zeros gives C1…Cn, and the last two blocks go out as C(n−1) cut to the length d of the plaintext's last block
    /// then Cn (CS1), in that order when d is a whole block and swapped otherwise (CS2), or always swapped (CS3, the
    /// Kerberos one). Needs more than one block.
    /// </summary>
    internal static byte[] ReferenceCts(byte[] key, byte[] iv, byte[] plaintext, int variant)
    {
        int last = plaintext.Length % 16 == 0 ? 16 : plaintext.Length % 16;
        byte[] padded = new byte[(plaintext.Length + 15) / 16 * 16];
        plaintext.CopyTo(padded, 0);
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] cbc = aes.EncryptCbc(padded, iv, PaddingMode.None);
        int n = cbc.Length / 16;
        ReadOnlySpan<byte> head = cbc.AsSpan(0, (n - 2) * 16), penultimate = cbc.AsSpan((n - 2) * 16, last), final = cbc.AsSpan((n - 1) * 16, 16);
        bool swap = variant == 3 || (variant == 2 && last != 16);
        return swap ? [.. head, .. final, .. penultimate] : [.. head, .. penultimate, .. final];
    }

    private static UInt128 ToUInt128(ReadOnlySpan<byte> bytes) => System.Buffers.Binary.BinaryPrimitives.ReadUInt128BigEndian(bytes);

    private static byte[] FromUInt128(UInt128 value)
    {
        byte[] bytes = new byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt128BigEndian(bytes, value);
        return bytes;
    }

    /// <summary>The AES feedback modes, each taking a 16-byte IV, over 37 bytes of plaintext: none needs padding.</summary>
    public static TheoryData<CKM> AesFeedbackModes =>
        [CKM.CKM_AES_OFB, CKM.CKM_AES_CFB1, CKM.CKM_AES_CFB8, CKM.CKM_AES_CFB64, CKM.CKM_AES_CFB128];

    private static byte[] ReferenceFeedback(CKM mechanism, byte[] plaintext) => mechanism switch
    {
        CKM.CKM_AES_OFB => ReferenceOfb(AesKey, Iv16, plaintext),
        CKM.CKM_AES_CFB1 => ReferenceCfb(AesKey, Iv16, plaintext, 1),
        CKM.CKM_AES_CFB8 => ReferenceCfb(AesKey, Iv16, plaintext, 8),
        CKM.CKM_AES_CFB64 => ReferenceCfb(AesKey, Iv16, plaintext, 64),
        CKM.CKM_AES_CFB128 => ReferenceCfb(AesKey, Iv16, plaintext, 128),
        _ => throw new ArgumentOutOfRangeException(nameof(mechanism)),
    };

    // Each feedback mode encrypts as SP 800-38A says, and decrypts its own ciphertext back. The modes keep the length,
    // so where the backend's wrapper says the token reports a longer output than it wrote, the case compares the
    // input's length of it.
    internal static void Assert_AesFeedbackMode_MatchesSp80038a(IPkcs11Backend backend, CKM mechanism, bool reportsTheOutputLength = true)
    {
        backend.RequireMechanism(mechanism);
        AssertEncryptsAndDecrypts(backend, CKK.CKK_AES, AesKey, new Mechanism(mechanism, Iv16), Plaintext37, ReferenceFeedback(mechanism, Plaintext37),
            reportsTheOutputLength);
    }

    // CKM_AES_CTS encrypts as one of the NIST ciphertext-stealing variants (tokens differ: Kryoptic gives CS1,
    // BouncyHsm CS3) for a plaintext of one block and a bit, of whole blocks and in between, and decrypts it back.
    public static TheoryData<int> CtsLengths => [17, 31, 32, 33, 48, 63];

    internal static void Assert_AesCts_IsNistCiphertextStealing(IPkcs11Backend backend, int length)
    {
        backend.RequireMechanism(CKM.CKM_AES_CTS);
        byte[] plaintext = [.. Enumerable.Range(0, length).Select(i => (byte)(0x30 + i))];
        var mechanism = new Mechanism(CKM.CKM_AES_CTS, Iv16);
        WithSession(backend, session =>
        {
            ObjectHandle handle = CreateSecret(session, CKK.CKK_AES, AesKey, CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT);
            try
            {
                byte[] ciphertext = Taken(() => session.Encrypt(mechanism, handle, plaintext), $"CKM_AES_CTS encryption of {length} bytes");
                int[] variants = [.. new[] { 1, 2, 3 }.Where(v => ReferenceCts(AesKey, Iv16, plaintext, v).AsSpan().SequenceEqual(ciphertext))];
                Assert.True(variants.Length > 0, $"CKM_AES_CTS of {length} bytes is none of CS1, CS2 and CS3: {Convert.ToHexStringLower(ciphertext)}.");
                Assert.Equal(plaintext, session.Decrypt(mechanism, handle, ciphertext));
            }
            finally { session.DestroyObject(handle); }
        });
    }

    private static void AssertEncryptsAndDecrypts(IPkcs11Backend backend, CKK keyType, byte[] key, Mechanism mechanism, byte[] plaintext, byte[] expected,
        bool reportsTheOutputLength = true)
    {
        WithSession(backend, session =>
        {
            ObjectHandle handle = CreateSecret(session, keyType, key, CKA.CKA_ENCRYPT, CKA.CKA_DECRYPT);
            try
            {
                byte[] ciphertext = Taken(() => session.Encrypt(mechanism, handle, plaintext), $"{mechanism.Type} encryption of {plaintext.Length} bytes");
                if (!reportsTheOutputLength)
                    ciphertext = ciphertext[..expected.Length];
                Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(ciphertext));
                byte[] decrypted = session.Decrypt(mechanism, handle, ciphertext);
                Assert.Equal(plaintext, reportsTheOutputLength ? decrypted : decrypted[..plaintext.Length]);
            }
            finally { session.DestroyObject(handle); }
        });
    }

    // CKM_AES_GMAC takes the IV as its parameter and gives the GCM tag of the data as additional data with no
    // plaintext (NIST SP 800-38D §3, PKCS#11 v3.2 §6.14.10); it verifies, and a changed tag does not.
    internal static void Assert_AesGmac_IsTheGcmTagOfTheData(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_AES_GMAC);
        byte[] iv = [.. Enumerable.Range(0, 12).Select(i => (byte)(0xF0 + i))];
        byte[] expected = new byte[16];
        using (var gcm = new AesGcm(AesKey, 16))
            gcm.Encrypt(iv, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, expected, Message);
        WithSession(backend, session =>
        {
            ObjectHandle handle = CreateSecret(session, CKK.CKK_AES, AesKey, CKA.CKA_SIGN, CKA.CKA_VERIFY);
            try
            {
                var mechanism = new Mechanism(CKM.CKM_AES_GMAC, iv);
                byte[] tag = Taken(() => session.Sign(mechanism, handle, Message), "CKM_AES_GMAC with a 12-byte IV");
                Assert.Equal(expected, tag);
                Assert.True(session.Verify(mechanism, handle, Message, tag));
                tag[^1] ^= 0x01;
                Assert.False(session.Verify(mechanism, handle, Message, tag));
            }
            finally { session.DestroyObject(handle); }
        });
    }

    // === Camellia ===============================================================

    // CBC_PAD over 37 bytes: two full blocks as CBC gives them, then the PKCS #7-padded rest (OpenSSL, as above).
    private static readonly byte[] CamelliaPlaintext37 = "the quick brown fox jumps over the la"u8.ToArray();
    private static readonly byte[] CamelliaCbcPadCiphertext = Convert.FromHexString(
        "caa77d1719b0f1b7b9bd801e637bad42b4968cd68fe4921065c87e393ff56873e0dd4545efed8d95036bacab945b6425");

    public static TheoryData<CKM> CamelliaModes => [CKM.CKM_CAMELLIA_ECB, CKM.CKM_CAMELLIA_CBC, CKM.CKM_CAMELLIA_CBC_PAD];

    // Camellia (RFC 3713) encrypts the known answer in each mode and decrypts it back. The ECB case runs the RFC's
    // own vector as well.
    internal static void Assert_Camellia_KnownAnswer(IPkcs11Backend backend, CKM mode)
    {
        backend.RequireMechanism(mode);
        (Mechanism mechanism, byte[] plaintext, byte[] expected) = mode switch
        {
            CKM.CKM_CAMELLIA_ECB => (new Mechanism(mode), CamelliaPlaintext, CamelliaEcbCiphertext),
            CKM.CKM_CAMELLIA_CBC => (new Mechanism(mode, Iv16), CamelliaPlaintext, CamelliaCbcCiphertext),
            CKM.CKM_CAMELLIA_CBC_PAD => (new Mechanism(mode, Iv16), CamelliaPlaintext37, CamelliaCbcPadCiphertext),
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
        AssertEncryptsAndDecrypts(backend, CKK.CKK_CAMELLIA, CamelliaKey, mechanism, plaintext, expected);
        if (mode == CKM.CKM_CAMELLIA_ECB)
            AssertEncryptsAndDecrypts(backend, CKK.CKK_CAMELLIA, CamelliaKey, mechanism, CamelliaKey,
                Convert.FromHexString("67673138549669730857065648eabe43"));
    }

    // === Poly1305 ===============================================================

    // CKM_POLY1305 under a CKK_POLY1305 key gives the RFC 8439 §2.5.2 tag, verifies it, and refuses a changed one.
    internal static void Assert_Poly1305_Rfc8439Vector(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_POLY1305);
        byte[] key = Convert.FromHexString("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        byte[] message = "Cryptographic Forum Research Group"u8.ToArray();
        byte[] expected = Convert.FromHexString("a8061dc1305136c6c22b8baf0c0127a9");
        WithSession(backend, session =>
        {
            ObjectHandle handle = CreateSecret(session, CKK.CKK_POLY1305, key, CKA.CKA_SIGN, CKA.CKA_VERIFY);
            try
            {
                var mechanism = new Mechanism(CKM.CKM_POLY1305);
                byte[] tag = Taken(() => session.Sign(mechanism, handle, message), "CKM_POLY1305 under a CKK_POLY1305 key");
                Assert.Equal(expected, tag);
                Assert.True(session.Verify(mechanism, handle, message, tag));
                tag[0] ^= 0x80;
                Assert.False(session.Verify(mechanism, handle, message, tag));
            }
            finally { session.DestroyObject(handle); }
        });
    }

    // The references themselves, against NIST SP 800-38A Appendix F (F.3.1, F.3.7, F.3.13, F.4.1: AES-128 CFB1,
    // CFB8, CFB128 and OFB) and RFC 3962 (CTS), so a case that fails points at the token and not at the reference.
    internal static void Assert_References_MatchSp80038aVectors()
    {
        byte[] key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");
        byte[] cfb1In = [0x6B, 0xC1];
        Assert.Equal("68b3", Convert.ToHexStringLower(ReferenceCfb(key, iv, cfb1In, 1)));
        Assert.Equal("3b79424c9c0dd436bace9e0ed4586a4f32b9",
            Convert.ToHexStringLower(ReferenceCfb(key, iv, Convert.FromHexString("6bc1bee22e409f96e93d7e117393172aae2d"), 8)));
        byte[] block = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a");
        Assert.Equal("3b3fd92eb72dad20333449f8e83cfb4a", Convert.ToHexStringLower(ReferenceCfb(key, iv, block, 128)));
        Assert.Equal("3b3fd92eb72dad20333449f8e83cfb4a", Convert.ToHexStringLower(ReferenceOfb(key, iv, block)));

        // RFC 3962 Appendix B, the first vector: Kerberos AES-CTS, which is CS3, with a zero IV.
        Assert.Equal("c6353568f2bf8cb4d8a580362da7ff7f97", Convert.ToHexStringLower(ReferenceCts(
            Convert.FromHexString("636869636b656e207465726979616b69"), new byte[16],
            Convert.FromHexString("4920776f756c64206c696b652074686520"), 3)));
    }
}
