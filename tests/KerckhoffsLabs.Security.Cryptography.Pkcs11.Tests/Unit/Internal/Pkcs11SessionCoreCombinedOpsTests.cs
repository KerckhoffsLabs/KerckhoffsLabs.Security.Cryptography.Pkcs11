using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

// These tests drive the gated legacy mechanisms/hashes on purpose (the secure-defaults policy check is the
// behaviour under test), so the compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11009

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the PKCS#11 combined dual-function operations
/// (<c>DigestEncrypt</c>, <c>DecryptDigest</c>, <c>DecryptVerify</c>). These are driven through
/// a <see cref="FakeModule"/> behind the real loader because neither SoftHSM nor opencryptoki
/// implements the C_*Update combined entry points, so the Integration suite never reaches them —
/// the multi-part loop, the CKR_BUFFER_TOO_SMALL retry, the two-call finals and the
/// CKR_OK/CKR_SIGNATURE_INVALID/throw arm of the verify tail are only exercisable with a fake.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionCoreCombinedOpsTests
{
    private const ulong SessionId = 11;

    /// <summary>
    /// Fake whose C_*Update entry points are an identity transform (output == input), so a
    /// round-trip's digest/encrypted/decrypted bytes are deterministic. The two-call finals report
    /// "no trailing bytes". <see cref="VerifyFinalRv"/> selects the verify outcome.
    /// </summary>
    private sealed class CombinedFake : SessionTestModule
    {
        public byte[] DigestOutput = [0xD1, 0xD2, 0xD3];
        public CKR VerifyFinalRv = CKR.CKR_OK;
        public readonly CKR UpdateRv = CKR.CKR_OK; // first C_*Update return value
        public bool FirstUpdateBufferTooSmall;     // emulate a token that demands a bigger buffer first
        public CKR VerifyInitRv = CKR.CKR_OK;
        public CKR DecryptInitRv = CKR.CKR_OK;
        public CKR DecryptFinalProbeRv = CKR.CKR_OK, DecryptFinalRv = CKR.CKR_OK;
        public byte[] LastBlock = [];
        public bool Canceled { get; private set; }
        public readonly List<string> Sequence = [];           // the digest or verify half's calls, in order
        public readonly List<byte[]> DigestedOrVerified = []; // what C_DigestUpdate / C_VerifyUpdate were given
        private bool _retried;

        private CKR Update(ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong outputLen)
        {
            int n = input.Length;
            // One-shot "buffer too small" probe: report the needed size without copying, then succeed.
            if (FirstUpdateBufferTooSmall && !_retried)
            {
                _retried = true;
                outputLen = (NativeCULong)n;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            input[..n].CopyTo(output.Span);
            outputLen = (NativeCULong)n;
            return UpdateRv;
        }

        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => CKR.CKR_OK;
        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => DecryptInitRv;
        protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => VerifyInitRv;

        protected override CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen)
            => Update(part, encryptedPart, ref encryptedPartLen);
        protected override CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Update(encryptedPart, part, ref partLen);
        protected override CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Update(encryptedPart, part, ref partLen);

        protected override CKR C_EncryptFinal(NativeCULong session, NativeBuffer<byte> lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
        { lastEncryptedPartLen = (NativeCULong)0; return CKR.CKR_OK; }
        protected override CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen)
        {
            lastPartLen = (NativeCULong)LastBlock.Length;
            if (lastPart.IsNull) return DecryptFinalProbeRv;
            LastBlock.CopyTo(lastPart.Span);
            return DecryptFinalRv;
        }

        protected override CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part)
        {
            Sequence.Add("C_DigestUpdate");
            DigestedOrVerified.Add(part.ToArray());
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part)
        {
            Sequence.Add("C_VerifyUpdate");
            DigestedOrVerified.Add(part.ToArray());
            return CKR.CKR_OK;
        }

        protected override CKR C_DigestFinal(NativeCULong session, NativeBuffer<byte> digest, ref NativeCULong digestLen)
        {
            if (!digest.IsNull) Sequence.Add("C_DigestFinal");
            if (digest.IsNull) { digestLen = (NativeCULong)DigestOutput.Length; return CKR.CKR_OK; }
            DigestOutput.AsSpan(0, DigestOutput.Length).CopyTo(digest.Span);
            digestLen = (NativeCULong)DigestOutput.Length;
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature)
        {
            Sequence.Add("C_VerifyFinal");
            return VerifyFinalRv;
        }
        protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) { Canceled = true; return CKR.CKR_OK; }
    }


    private static Mechanism Sha256() => new(CKM.CKM_SHA256);
    private static Mechanism AesGcm() => new(CKM.CKM_AES_GCM);
    private static Mechanism HmacSha256() => new(CKM.CKM_SHA256_HMAC);

    // === DigestEncrypt ======================================================

    [Fact]
    public void DigestEncrypt_Ok_ReturnsDigestAndEncryptedData()
    {
        using var fake = new CombinedFake { DigestOutput = [1, 2, 3, 4] };
        using var s = fake.CreateSession(SessionId);
        Mechanism digestMech = Sha256(), encMech = AesGcm();
        byte[] data = [10, 20, 30];

        s.DigestEncrypt(digestMech, encMech, new ObjectHandle(1), data, out byte[] digest, out byte[] encrypted);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, digest);
        Assert.Equal(data, encrypted); // identity transform
    }

    [Fact]
    public void DigestEncrypt_UpdateBufferTooSmall_RetriesAndSucceeds()
    {
        using var fake = new CombinedFake { FirstUpdateBufferTooSmall = true };
        using var s = fake.CreateSession(SessionId);
        Mechanism digestMech = Sha256(), encMech = AesGcm();
        byte[] data = [9, 8, 7, 6, 5];

        s.DigestEncrypt(digestMech, encMech, new ObjectHandle(1), data, out _, out byte[] encrypted);

        Assert.Equal(data, encrypted);
    }

    // === DecryptDigest ======================================================

    [Fact]
    public void DecryptDigest_Ok_ReturnsDigestAndDecryptedData()
    {
        using var fake = new CombinedFake { DigestOutput = [0xAA] };
        using var s = fake.CreateSession(SessionId);
        Mechanism digestMech = Sha256(), decMech = AesGcm();
        byte[] data = [42, 43];

        s.DecryptDigest(digestMech, decMech, new ObjectHandle(1), data, out byte[] digest, out byte[] decrypted);

        Assert.Equal(new byte[] { 0xAA }, digest);
        Assert.Equal(data, decrypted);
    }

    // C_DecryptDigestUpdate digests only the plaintext it returns (PKCS#11 v3.2 §5.13): the block a mechanism
    // held back comes out of C_DecryptFinal, and it reaches the digest through C_DigestUpdate before
    // C_DigestFinal. Without it a CBC-PAD message's digest leaves out its last block. An empty final part
    // makes no C_DigestUpdate.
    [Theory]
    [InlineData(new byte[] { 7, 8 })]
    [InlineData(new byte[0])]
    public void DecryptDigest_Stream_DigestsTheFinalPart_BeforeDigestFinal(byte[] lastBlock)
    {
        using var fake = new CombinedFake { LastBlock = lastBlock };
        using var s = fake.CreateSession(SessionId);
        using var input = new MemoryStream([1, 2, 3]);
        using var output = new MemoryStream();

        s.DecryptDigest(Sha256(), AesGcm(), new ObjectHandle(1), input, output, bufferLength: 2);

        Assert.Equal([1, 2, 3, .. lastBlock], output.ToArray());
        Assert.Equal(lastBlock.Length > 0 ? ["C_DigestUpdate", "C_DigestFinal"] : ["C_DigestFinal"], fake.Sequence);
        Assert.Equal(lastBlock.Length > 0 ? [lastBlock] : [], fake.DigestedOrVerified);
    }

    // DigestEncrypt digests its input, all of which went through C_DigestEncryptUpdate: the ciphertext
    // C_EncryptFinal returns is not digested.
    [Fact]
    public void DigestEncrypt_Stream_DigestsNoFinalPart()
    {
        using var fake = new CombinedFake();
        using var s = fake.CreateSession(SessionId);
        using var input = new MemoryStream([1, 2, 3]);
        using var output = new MemoryStream();

        s.DigestEncrypt(Sha256(), AesGcm(), new ObjectHandle(1), input, output, bufferLength: 2);

        Assert.Equal(["C_DigestFinal"], fake.Sequence);
    }

    // === DecryptVerify ======================================================

    [Fact]
    public void DecryptVerify_Ok_SetsValidTrue()
    {
        using var fake = new CombinedFake { VerifyFinalRv = CKR.CKR_OK };
        using var s = fake.CreateSession(SessionId);
        Mechanism verifyMech = HmacSha256(), decMech = AesGcm();
        byte[] data = [1, 2, 3];

        bool isValid = s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
            data, signature: new byte[32], out byte[] decrypted);

        Assert.True(isValid);
        Assert.Equal(data, decrypted);
    }

    // CKR_SIGNATURE_LEN_RANGE is a signature invalid solely because of its length (PKCS#11), so it
    // does not verify either.
    [Theory]
    [InlineData(CKR.CKR_SIGNATURE_INVALID)]
    [InlineData(CKR.CKR_SIGNATURE_LEN_RANGE)]
    public void DecryptVerify_SignatureInvalidOrWrongLength_SetsValidFalse(CKR verdict)
    {
        using var fake = new CombinedFake { VerifyFinalRv = verdict };
        using var s = fake.CreateSession(SessionId);
        Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        bool isValid = s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
            data: [1, 2, 3], signature: [9, 9], out _);

        Assert.False(isValid);
    }

    [Fact]
    public void DecryptVerify_VerifyFinalOtherError_Throws()
    {
        using var fake = new CombinedFake { VerifyFinalRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
                data: [1, 2, 3], signature: new byte[32], out _));
    }

    [Fact]
    public void DecryptVerify_VerifyInitError_Throws()
    {
        using var fake = new CombinedFake { VerifyInitRv = CKR.CKR_KEY_HANDLE_INVALID };
        using var s = fake.CreateSession(SessionId);
        Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
                data: [1, 2, 3], signature: [9, 9], out _));
    }

    // The stream overload: the decrypt half's init and final are checked like the verify half's,
    // the final block reaches the output, and a completed operation is not cancelled on the way out.
    private static bool DecryptVerifyStream(Pkcs11SessionCore s, byte[] input, out byte[] output)
    {
        using var inStream = new MemoryStream(input);
        using var outStream = new MemoryStream();
        bool isValid = s.DecryptVerify(HmacSha256(), new ObjectHandle(2), AesGcm(), new ObjectHandle(1),
            inStream, outStream, signature: new byte[32], bufferLength: 2);
        output = outStream.ToArray();
        return isValid;
    }

    [Fact]
    public void DecryptVerify_Stream_WritesTheFinalBlock_AndDoesNotCancel()
    {
        using var fake = new CombinedFake { LastBlock = [7, 8] };
        using var s = fake.CreateSession(SessionId);

        Assert.True(DecryptVerifyStream(s, [1, 2, 3], out byte[] output));

        Assert.Equal(new byte[] { 1, 2, 3, 7, 8 }, output);
        Assert.False(fake.Canceled);
    }

    // The DecryptVerify side of DecryptDigest_Stream_DigestsTheFinalPart_BeforeDigestFinal: C_DecryptVerifyUpdate
    // verifies only the plaintext it returns, and the final part goes to C_VerifyUpdate before C_VerifyFinal.
    [Theory]
    [InlineData(new byte[] { 7, 8 })]
    [InlineData(new byte[0])]
    public void DecryptVerify_Stream_VerifiesTheFinalPart_BeforeVerifyFinal(byte[] lastBlock)
    {
        using var fake = new CombinedFake { LastBlock = lastBlock };
        using var s = fake.CreateSession(SessionId);

        Assert.True(DecryptVerifyStream(s, [1, 2, 3], out byte[] output));

        Assert.Equal([1, 2, 3, .. lastBlock], output);
        Assert.Equal(lastBlock.Length > 0 ? ["C_VerifyUpdate", "C_VerifyFinal"] : ["C_VerifyFinal"], fake.Sequence);
        Assert.Equal(lastBlock.Length > 0 ? [lastBlock] : [], fake.DigestedOrVerified);
    }

    [Theory]
    [InlineData("init")]
    [InlineData("final probe")]
    [InlineData("final")]
    public void DecryptVerify_Stream_DecryptError_Throws(string step)
    {
        using var fake = new CombinedFake { LastBlock = [7] };
        switch (step)
        {
            case "init": fake.DecryptInitRv = CKR.CKR_KEY_HANDLE_INVALID; break;
            case "final probe": fake.DecryptFinalProbeRv = CKR.CKR_KEY_HANDLE_INVALID; break;
            default: fake.DecryptFinalRv = CKR.CKR_KEY_HANDLE_INVALID; break;
        }
        using var s = fake.CreateSession(SessionId);

        var e = Assert.ThrowsAny<Pkcs11Exception>(() => DecryptVerifyStream(s, [1, 2, 3], out _));
        Assert.Equal(CKR.CKR_KEY_HANDLE_INVALID, e.ReturnValue);
    }

    // === Insecure-mechanism gate fires on either mechanism ==================

    [Fact]
    public void DigestEncrypt_InsecureEncryptionMechanism_IsRejected()
    {
        using var fake = new CombinedFake();
        using var s = fake.CreateSession(SessionId);
        Mechanism digestMech = Sha256(), insecure = new(CKM.CKM_AES_ECB);

        Assert.Throws<CryptoPolicyViolationException>(() =>
            s.DigestEncrypt(digestMech, insecure, new ObjectHandle(1), [1], out _, out _));
    }
}
