using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the PKCS#11 combined dual-function operations
/// (<c>DigestEncrypt</c>, <c>DecryptDigest</c>, <c>DecryptVerify</c>). These are driven through
/// the <see cref="ILowLevelPkcs11Library"/> seam because neither SoftHSM nor opencryptoki
/// implements the C_*Update combined entry points, so the Integration suite never reaches them —
/// the multi-part loop, the CKR_BUFFER_TOO_SMALL retry, the two-call finals and the
/// CKR_OK/CKR_SIGNATURE_INVALID/throw arm of the verify tail are only exercisable with a fake.
/// </summary>
public sealed class Pkcs11SessionCombinedOpsTests
{
    private const ulong SessionId = 11;

    /// <summary>
    /// Fake whose C_*Update entry points are an identity transform (output == input), so a
    /// round-trip's digest/encrypted/decrypted bytes are deterministic. The two-call finals report
    /// "no trailing bytes". <see cref="VerifyFinalRv"/> selects the verify outcome.
    /// </summary>
    private sealed class CombinedFake : FakeLowLevelPkcs11Library
    {
        public byte[] DigestOutput = [0xD1, 0xD2, 0xD3];
        public CKR VerifyFinalRv = CKR.CKR_OK;
        public CKR UpdateRv = CKR.CKR_OK;          // first C_*Update return value
        public bool FirstUpdateBufferTooSmall;     // emulate a token that demands a bigger buffer first
        public CKR VerifyInitRv = CKR.CKR_OK;
        private bool _retried;

        private CKR Update(byte[] input, NativeCULong inputLen, byte[] output, ref NativeCULong outputLen)
        {
            int n = (int)inputLen;
            // One-shot "buffer too small" probe: report the needed size without copying, then succeed.
            if (FirstUpdateBufferTooSmall && !_retried)
            {
                _retried = true;
                outputLen = (NativeCULong)n;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            Array.Copy(input, output, n);
            outputLen = (NativeCULong)n;
            return UpdateRv;
        }

        public override CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism) => CKR.CKR_OK;
        public override CKR C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        public override CKR C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        public override CKR C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => VerifyInitRv;

        public override CKR C_DigestEncryptUpdate(NativeCULong session, byte[] part, NativeCULong partLen, byte[] encryptedPart, ref NativeCULong encryptedPartLen)
            => Update(part, partLen, encryptedPart, ref encryptedPartLen);
        public override CKR C_DecryptDigestUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
            => Update(encryptedPart, encryptedPartLen, part, ref partLen);
        public override CKR C_DecryptVerifyUpdate(NativeCULong session, byte[] encryptedPart, NativeCULong encryptedPartLen, byte[] part, ref NativeCULong partLen)
            => Update(encryptedPart, encryptedPartLen, part, ref partLen);

        public override CKR C_EncryptFinal(NativeCULong session, byte[]? lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
        { lastEncryptedPartLen = (NativeCULong)0; return CKR.CKR_OK; }
        public override CKR C_DecryptFinal(NativeCULong session, byte[]? lastPart, ref NativeCULong lastPartLen)
        { lastPartLen = (NativeCULong)0; return CKR.CKR_OK; }

        public override CKR C_DigestFinal(NativeCULong session, byte[]? digest, ref NativeCULong digestLen)
        {
            if (digest is null) { digestLen = (NativeCULong)DigestOutput.Length; return CKR.CKR_OK; }
            Array.Copy(DigestOutput, digest, DigestOutput.Length);
            digestLen = (NativeCULong)DigestOutput.Length;
            return CKR.CKR_OK;
        }

        public override CKR C_VerifyFinal(NativeCULong session, byte[] signature, NativeCULong signatureLen) => VerifyFinalRv;
        public override CKR C_SessionCancel(NativeCULong session, NativeCULong flags) => CKR.CKR_OK;
    }

    private static Pkcs11Session NewSession(CombinedFake fake) => new(fake, SessionId);

    private static Mechanism Sha256() => new(CKM.CKM_SHA256);
    private static Mechanism AesGcm() => new(CKM.CKM_AES_GCM);
    private static Mechanism HmacSha256() => new(CKM.CKM_SHA256_HMAC);

    // === DigestEncrypt ======================================================

    [Fact]
    public void DigestEncrypt_Ok_ReturnsDigestAndEncryptedData()
    {
        var fake = new CombinedFake { DigestOutput = [1, 2, 3, 4] };
        var s = NewSession(fake);
        using Mechanism digestMech = Sha256(), encMech = AesGcm();
        byte[] data = [10, 20, 30];

        s.DigestEncrypt(digestMech, encMech, new ObjectHandle(1), data, out byte[] digest, out byte[] encrypted);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, digest);
        Assert.Equal(data, encrypted); // identity transform
    }

    [Fact]
    public void DigestEncrypt_UpdateBufferTooSmall_RetriesAndSucceeds()
    {
        var fake = new CombinedFake { FirstUpdateBufferTooSmall = true };
        var s = NewSession(fake);
        using Mechanism digestMech = Sha256(), encMech = AesGcm();
        byte[] data = [9, 8, 7, 6, 5];

        s.DigestEncrypt(digestMech, encMech, new ObjectHandle(1), data, out _, out byte[] encrypted);

        Assert.Equal(data, encrypted);
    }

    // === DecryptDigest ======================================================

    [Fact]
    public void DecryptDigest_Ok_ReturnsDigestAndDecryptedData()
    {
        var fake = new CombinedFake { DigestOutput = [0xAA] };
        var s = NewSession(fake);
        using Mechanism digestMech = Sha256(), decMech = AesGcm();
        byte[] data = [42, 43];

        s.DecryptDigest(digestMech, decMech, new ObjectHandle(1), data, out byte[] digest, out byte[] decrypted);

        Assert.Equal(new byte[] { 0xAA }, digest);
        Assert.Equal(data, decrypted);
    }

    // === DecryptVerify ======================================================

    [Fact]
    public void DecryptVerify_Ok_SetsValidTrue()
    {
        var s = NewSession(new CombinedFake { VerifyFinalRv = CKR.CKR_OK });
        using Mechanism verifyMech = HmacSha256(), decMech = AesGcm();
        byte[] data = [1, 2, 3];

        s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
            data, signature: [9, 9], out byte[] decrypted, out bool isValid);

        Assert.True(isValid);
        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void DecryptVerify_SignatureInvalid_SetsValidFalse()
    {
        var s = NewSession(new CombinedFake { VerifyFinalRv = CKR.CKR_SIGNATURE_INVALID });
        using Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
            data: [1, 2, 3], signature: [9, 9], out _, out bool isValid);

        Assert.False(isValid);
    }

    [Fact]
    public void DecryptVerify_VerifyFinalOtherError_Throws()
    {
        var s = NewSession(new CombinedFake { VerifyFinalRv = CKR.CKR_DEVICE_ERROR });
        using Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
                data: [1, 2, 3], signature: [9, 9], out _, out _));
    }

    [Fact]
    public void DecryptVerify_VerifyInitError_Throws()
    {
        var s = NewSession(new CombinedFake { VerifyInitRv = CKR.CKR_KEY_HANDLE_INVALID });
        using Mechanism verifyMech = HmacSha256(), decMech = AesGcm();

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.DecryptVerify(verifyMech, new ObjectHandle(2), decMech, new ObjectHandle(1),
                data: [1, 2, 3], signature: [9, 9], out _, out _));
    }

    // === Insecure-mechanism gate fires on either mechanism ==================

    [Fact]
    public void DigestEncrypt_InsecureEncryptionMechanism_IsRejected()
    {
        var s = NewSession(new CombinedFake());
        using Mechanism digestMech = Sha256(), insecure = new(CKM.CKM_AES_ECB);

        Assert.Throws<InsecureOperationException>(() =>
            s.DigestEncrypt(digestMech, insecure, new ObjectHandle(1), [1], out _, out _));
    }
}
