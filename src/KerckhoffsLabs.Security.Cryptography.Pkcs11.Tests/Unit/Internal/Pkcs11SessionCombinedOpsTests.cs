using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

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
public sealed class Pkcs11SessionCombinedOpsTests
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
        public CKR UpdateRv = CKR.CKR_OK;          // first C_*Update return value
        public bool FirstUpdateBufferTooSmall;     // emulate a token that demands a bigger buffer first
        public CKR VerifyInitRv = CKR.CKR_OK;
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
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
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
        { lastPartLen = (NativeCULong)0; return CKR.CKR_OK; }

        protected override CKR C_DigestFinal(NativeCULong session, NativeBuffer<byte> digest, ref NativeCULong digestLen)
        {
            if (digest.IsNull) { digestLen = (NativeCULong)DigestOutput.Length; return CKR.CKR_OK; }
            DigestOutput.AsSpan(0, DigestOutput.Length).CopyTo(digest.Span);
            digestLen = (NativeCULong)DigestOutput.Length;
            return CKR.CKR_OK;
        }

        protected override CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature) => VerifyFinalRv;
        protected override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_OK;
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

    // === DecryptVerify ======================================================

    [Fact]
    public void DecryptVerify_Ok_SetsValidTrue()
    {
        using var fake = new CombinedFake { VerifyFinalRv = CKR.CKR_OK };
        using var s = fake.CreateSession(SessionId);
        Mechanism verifyMech = HmacSha256(), decMech = AesGcm();
        byte[] data = [1, 2, 3];

        s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
            data, signature: [9, 9], out byte[] decrypted, out bool isValid);

        Assert.True(isValid);
        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void DecryptVerify_SignatureInvalid_SetsValidFalse()
    {
        using var fake = new CombinedFake { VerifyFinalRv = CKR.CKR_SIGNATURE_INVALID };
        using var s = fake.CreateSession(SessionId);
        Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
            data: [1, 2, 3], signature: [9, 9], out _, out bool isValid);

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
                data: [1, 2, 3], signature: [9, 9], out _, out _));
    }

    [Fact]
    public void DecryptVerify_VerifyInitError_Throws()
    {
        using var fake = new CombinedFake { VerifyInitRv = CKR.CKR_KEY_HANDLE_INVALID };
        using var s = fake.CreateSession(SessionId);
        Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
                data: [1, 2, 3], signature: [9, 9], out _, out _));
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
