using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the PKCS#11 v3.2 surface of <see cref="Pkcs11Session"/>:
/// encapsulate/decapsulate, authenticated wrap/unwrap, signature-only verify (one-shot and
/// streaming), and session validation flags. These entry points are absent from SoftHSM and only
/// partially present on opencryptoki, so the Integration suite cannot reach the buffer-probe,
/// resize, verify-tail and CKR-&gt;exception arms — they are exercised here through the
/// <see cref="ILowLevelPkcs11Library"/> seam.
/// </summary>
public sealed class Pkcs11SessionV32Tests
{
    private const ulong SessionId = 11;

    private sealed class V32Fake : FakeLowLevelPkcs11Library
    {
        public byte[] Ciphertext = [0xC0, 0xC1, 0xC2];
        public byte[] Wrapped = [0xAA, 0xBB, 0xCC];
        public ulong SharedId = 50, UnwrappedId = 60;
        public ulong ValidationFlags = 1;
        public int? WrapSecondLen;
        public bool EncapsProbeBufferTooSmall;

        public CKR EncapsRv = CKR.CKR_OK, DecapsRv = CKR.CKR_OK, WrapAuthRv = CKR.CKR_OK,
            UnwrapAuthRv = CKR.CKR_OK, VerifySigInitRv = CKR.CKR_OK, VerifySigRv = CKR.CKR_OK,
            VerifySigFinalRv = CKR.CKR_OK, ValidationRv = CKR.CKR_OK;

        public int VerifyUpdateCalls { get; private set; }
        public byte[]? CapturedAad;

        public override CKR C_EncapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
        {
            derivedKey = (NativeCULong)SharedId;
            if (ciphertext is null)
            {
                ciphertextLen = (NativeCULong)Ciphertext.Length;
                return EncapsProbeBufferTooSmall ? CKR.CKR_BUFFER_TOO_SMALL : EncapsRv;
            }
            Array.Copy(Ciphertext, ciphertext, Ciphertext.Length);
            ciphertextLen = (NativeCULong)Ciphertext.Length;
            return EncapsRv;
        }

        public override CKR C_DecapsulateKey(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] ciphertext, NativeCULong ciphertextLen, ref NativeCULong derivedKey)
        { derivedKey = (NativeCULong)SharedId; return DecapsRv; }

        public override CKR C_WrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, byte[] associatedData, NativeCULong associatedDataLen, byte[]? wrappedKey, ref NativeCULong wrappedKeyLen)
        {
            CapturedAad = associatedData[..(int)associatedDataLen];
            if (wrappedKey is null) { wrappedKeyLen = (NativeCULong)Wrapped.Length; return WrapAuthRv; }
            int n = WrapSecondLen ?? Wrapped.Length;
            Array.Copy(Wrapped, wrappedKey, Math.Min(n, wrappedKey.Length));
            wrappedKeyLen = (NativeCULong)n;
            return WrapAuthRv;
        }

        public override CKR C_UnwrapKeyAuthenticated(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong unwrappingKey, byte[] wrappedKey, NativeCULong wrappedKeyLen, CK_ATTRIBUTE[] template, NativeCULong attributeCount, byte[] associatedData, NativeCULong associatedDataLen, ref NativeCULong key)
        { CapturedAad = associatedData[..(int)associatedDataLen]; key = (NativeCULong)UnwrappedId; return UnwrapAuthRv; }

        public override CKR C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, byte[] signature, NativeCULong signatureLen) => VerifySigInitRv;
        public override CKR C_VerifySignature(NativeCULong session, byte[] data, NativeCULong dataLen) => VerifySigRv;
        public override CKR C_VerifySignatureUpdate(NativeCULong session, byte[] part, NativeCULong partLen) { VerifyUpdateCalls++; return CKR.CKR_OK; }
        public override CKR C_VerifySignatureFinal(NativeCULong session) => VerifySigFinalRv;

        public override CKR C_GetSessionValidationFlags(NativeCULong session, NativeCULong type, ref NativeCULong flags)
        { flags = (NativeCULong)ValidationFlags; return ValidationRv; }
    }

    private static Pkcs11Session NewSession(V32Fake fake) => new(fake, SessionId);

    // === EncapsulateKey =====================================================

    [Fact]
    public void EncapsulateKey_Ok_ReturnsCiphertextAndHandle()
    {
        var s = NewSession(new V32Fake { Ciphertext = [1, 2, 3, 4], SharedId = 0x77 });
        using var mech = new Mechanism(CKM.CKM_ML_KEM);

        var (ciphertext, shared) = s.EncapsulateKey(mech, new ObjectHandle(1), []);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, ciphertext);
        Assert.Equal(0x77UL, shared.ObjectId);
    }

    [Fact]
    public void EncapsulateKey_ProbeBufferTooSmall_StillSucceeds()
    {
        var s = NewSession(new V32Fake { EncapsProbeBufferTooSmall = true, Ciphertext = [5, 6] });
        using var mech = new Mechanism(CKM.CKM_ML_KEM);

        var (ciphertext, _) = s.EncapsulateKey(mech, new ObjectHandle(1), []);

        Assert.Equal(new byte[] { 5, 6 }, ciphertext);
    }

    [Fact]
    public void EncapsulateKey_Error_Throws()
    {
        var s = NewSession(new V32Fake { EncapsRv = CKR.CKR_KEY_HANDLE_INVALID });
        using var mech = new Mechanism(CKM.CKM_ML_KEM);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.EncapsulateKey(mech, new ObjectHandle(1), []));
    }

    // === DecapsulateKey =====================================================

    [Fact]
    public void DecapsulateKey_Ok_ReturnsHandle()
    {
        var s = NewSession(new V32Fake { SharedId = 0x88 });
        using var mech = new Mechanism(CKM.CKM_ML_KEM);
        Assert.Equal(0x88UL, s.DecapsulateKey(mech, new ObjectHandle(1), [1, 2, 3], []).ObjectId);
    }

    [Fact]
    public void DecapsulateKey_Error_Throws()
    {
        var s = NewSession(new V32Fake { DecapsRv = CKR.CKR_MECHANISM_PARAM_INVALID });
        using var mech = new Mechanism(CKM.CKM_ML_KEM);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.DecapsulateKey(mech, new ObjectHandle(1), [1, 2, 3], []));
    }

    // === WrapKeyAuthenticated ===============================================

    [Fact]
    public void WrapKeyAuthenticated_Ok_ReturnsBytesAndBindsAad()
    {
        var fake = new V32Fake { Wrapped = [9, 8, 7] };
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_AES_GCM);

        byte[] wrapped = s.WrapKeyAuthenticated(mech, new ObjectHandle(1), new ObjectHandle(2), [0xAA, 0xBB]);

        Assert.Equal(new byte[] { 9, 8, 7 }, wrapped);
        Assert.Equal(new byte[] { 0xAA, 0xBB }, fake.CapturedAad);
    }

    [Fact]
    public void WrapKeyAuthenticated_SecondCallShorter_ResizesDown()
    {
        var s = NewSession(new V32Fake { Wrapped = [1, 2, 3, 4], WrapSecondLen = 2 });
        using var mech = new Mechanism(CKM.CKM_AES_GCM);
        Assert.Equal(new byte[] { 1, 2 }, s.WrapKeyAuthenticated(mech, new ObjectHandle(1), new ObjectHandle(2), []));
    }

    [Fact]
    public void WrapKeyAuthenticated_Error_Throws()
    {
        var s = NewSession(new V32Fake { WrapAuthRv = CKR.CKR_KEY_UNEXTRACTABLE });
        using var mech = new Mechanism(CKM.CKM_AES_GCM);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.WrapKeyAuthenticated(mech, new ObjectHandle(1), new ObjectHandle(2), []));
    }

    // === UnwrapKeyAuthenticated =============================================

    [Fact]
    public void UnwrapKeyAuthenticated_Ok_ReturnsHandleAndBindsAad()
    {
        var fake = new V32Fake { UnwrappedId = 0x99 };
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_AES_GCM);

        ObjectHandle h = s.UnwrapKeyAuthenticated(mech, new ObjectHandle(1), [1, 2, 3], [0xCC], []);

        Assert.Equal(0x99UL, h.ObjectId);
        Assert.Equal(new byte[] { 0xCC }, fake.CapturedAad);
    }

    [Fact]
    public void UnwrapKeyAuthenticated_Error_Throws()
    {
        var s = NewSession(new V32Fake { UnwrapAuthRv = CKR.CKR_AEAD_DECRYPT_FAILED });
        using var mech = new Mechanism(CKM.CKM_AES_GCM);
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.UnwrapKeyAuthenticated(mech, new ObjectHandle(1), [1, 2, 3], [0xCC], []));
    }

    // === VerifySignature (one-shot) =========================================

    [Fact]
    public void VerifySignature_OneShot_Ok_ReturnsTrue()
    {
        var s = NewSession(new V32Fake { VerifySigRv = CKR.CKR_OK });
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        Assert.True(s.VerifySignature(mech, new ObjectHandle(1), [9, 9], [1, 2, 3]));
    }

    [Fact]
    public void VerifySignature_OneShot_SignatureInvalid_ReturnsFalse()
    {
        var s = NewSession(new V32Fake { VerifySigRv = CKR.CKR_SIGNATURE_INVALID });
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        Assert.False(s.VerifySignature(mech, new ObjectHandle(1), [9, 9], [1, 2, 3]));
    }

    [Fact]
    public void VerifySignature_OneShot_OtherError_Throws()
    {
        var s = NewSession(new V32Fake { VerifySigRv = CKR.CKR_DEVICE_ERROR });
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], [1, 2, 3]));
    }

    [Fact]
    public void VerifySignature_OneShot_InitError_Throws()
    {
        var s = NewSession(new V32Fake { VerifySigInitRv = CKR.CKR_KEY_HANDLE_INVALID });
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], [1, 2, 3]));
    }

    // === VerifySignature (stream) ===========================================

    [Fact]
    public void VerifySignature_Stream_Ok_ReturnsTrue_AndFeedsEveryChunk()
    {
        var fake = new V32Fake { VerifySigFinalRv = CKR.CKR_OK };
        var s = NewSession(fake);
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        using var input = new MemoryStream([1, 2, 3, 4, 5]);

        bool ok = s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input, bufferLength: 2);

        Assert.True(ok);
        Assert.Equal(3, fake.VerifyUpdateCalls);
    }

    [Fact]
    public void VerifySignature_Stream_SignatureInvalid_ReturnsFalse()
    {
        var s = NewSession(new V32Fake { VerifySigFinalRv = CKR.CKR_SIGNATURE_INVALID });
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.False(s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input));
    }

    [Fact]
    public void VerifySignature_Stream_OtherError_Throws()
    {
        var s = NewSession(new V32Fake { VerifySigFinalRv = CKR.CKR_DEVICE_ERROR });
        using var mech = new Mechanism(CKM.CKM_ECDSA);
        using var input = new MemoryStream([1, 2, 3]);

        Assert.ThrowsAny<Pkcs11Exception>(() => s.VerifySignature(mech, new ObjectHandle(1), [9, 9], input));
    }

    // === GetSessionValidationFlags ==========================================

    [Fact]
    public void GetSessionValidationFlags_Ok_ReturnsFlags()
    {
        var s = NewSession(new V32Fake { ValidationFlags = 0x5 });
        Assert.Equal(0x5UL, s.GetSessionValidationFlags(CksValidationFlagsType.CKS_LAST_VALIDATION_OK));
    }

    [Fact]
    public void GetSessionValidationFlags_Error_Throws()
    {
        var s = NewSession(new V32Fake { ValidationRv = CKR.CKR_FUNCTION_NOT_SUPPORTED });
        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.GetSessionValidationFlags(CksValidationFlagsType.CKS_LAST_VALIDATION_OK));
    }
}
