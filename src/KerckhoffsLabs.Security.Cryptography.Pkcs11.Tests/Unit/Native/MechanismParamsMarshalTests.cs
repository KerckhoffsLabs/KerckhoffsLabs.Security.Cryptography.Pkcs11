using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Marshalling round-trip coverage for the pointer-bearing <c>MechanismParameters</c> wrappers. Each
/// case builds the wrapper, takes its low-level <c>CK_*</c> structure, writes it through the
/// platform-correct marshaller (<see cref="UnmanagedMemory"/> → <c>PackedDispatch</c>) and reads it
/// back, then asserts the length fields and that the embedded pointers reference the right bytes.
/// The bundled SoftHSM implements few of these mechanisms, so this is the primary correctness check
/// on the parameter structs without a token. Mirrors the existing RC2 / SP800-108 marshal tests.
/// </summary>
public sealed class MechanismParamsMarshalTests
{
    // Writes the boxed CK_* struct through the marshaller and reads it back as T. The pointers in the
    // result reference the scope the struct was built into, so the caller must keep that scope alive
    // (a `using` in scope) while dereferencing them.
    private static T Marshalled<T>(object raw) where T : struct
    {
        int size = UnmanagedMemory.SizeOf<T>();
        IntPtr mem = UnmanagedMemory.Allocate(size);
        try
        {
            UnmanagedMemory.Write(mem, raw);
            return UnmanagedMemory.Read<T>(mem);
        }
        finally { UnmanagedMemory.Free(ref mem); }
    }

    // === AES-GCM (CK_GCM_PARAMS) ==========================================

    [Fact]
    public void AesGcm_RoundTrips_IvAadAndLengths()
    {
        byte[] iv = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        byte[] aad = [0xAA, 0xBB, 0xCC];
        var p = new CkmAesGcmParams(iv, aad, tagBits: 96);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_GCM_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)iv.Length, (ulong)s.IvLen);
        // IvBits is a legacy field (PKCS#11 v3.2 §2.5.13); we always marshal it as 0 since the IV
        // length is carried by IvLen and some tokens reject a non-zero value.
        Assert.Equal(0UL, (ulong)s.IvBits);
        Assert.Equal((ulong)aad.Length, (ulong)s.AADLen);
        Assert.Equal(96UL, (ulong)s.TagBits);
        Assert.NotEqual(IntPtr.Zero, s.Iv);
        Assert.Equal(iv, UnmanagedMemory.Read(s.Iv, iv.Length));
        Assert.NotEqual(IntPtr.Zero, s.AAD);
        Assert.Equal(aad, UnmanagedMemory.Read(s.AAD, aad.Length));
    }

    [Fact]
    public void AesGcm_EmptyAad_NullPointerZeroLen()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        var p = new CkmAesGcmParams(iv, default, tagBits: 128);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_GCM_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(0UL, (ulong)s.AADLen);
        Assert.Equal(IntPtr.Zero, s.AAD);
    }

    [Theory]
    [InlineData(24)]   // below 32
    [InlineData(136)]  // above 128
    [InlineData(100)]  // not a multiple of 8
    public void AesGcm_RejectsBadTagBits(int tagBits) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new CkmAesGcmParams(new byte[12], default, tagBits));

    [Fact]
    public void AesGcm_RejectsEmptyIv() =>
        Assert.Throws<ArgumentException>(() => new CkmAesGcmParams(default, default, 128));

    // === RSA-OAEP (CK_RSA_PKCS_OAEP_PARAMS) ===============================

    [Fact]
    public void Oaep_RoundTrips_WithSourceData()
    {
        byte[] src = [0xDE, 0xAD, 0xBE, 0xEF];
        var p = new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, src);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_RSA_PKCS_OAEP_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA256, (ulong)s.HashAlg);
        Assert.Equal((ulong)CKG.CKG_MGF1_SHA256, (ulong)s.Mgf);
        Assert.Equal(CKZ.CKZ_DATA_SPECIFIED, (ulong)s.Source);
        Assert.Equal((ulong)src.Length, (ulong)s.SourceDataLen);
        Assert.Equal(src, UnmanagedMemory.Read(s.SourceData, src.Length));
    }

    [Fact]
    public void Oaep_NoSourceData_NullPointerZeroLen()
    {
        var p = new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_RSA_PKCS_OAEP_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(CKZ.CKZ_DATA_SPECIFIED, (ulong)s.Source);
        Assert.Equal(0UL, (ulong)s.SourceDataLen);
        Assert.Equal(IntPtr.Zero, s.SourceData);
    }

    // === RSA-PSS (CK_RSA_PKCS_PSS_PARAMS) =================================

    [Fact]
    public void Pss_RoundTrips_HashMgfSalt()
    {
        var p = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_RSA_PKCS_PSS_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA256, (ulong)s.HashAlg);
        Assert.Equal((ulong)CKG.CKG_MGF1_SHA256, (ulong)s.Mgf);
        Assert.Equal(32UL, (ulong)s.Len);
    }

    [Fact]
    public void Pss_RejectsNegativeSalt() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, -1));

    // === ECDH1 derive (CK_ECDH1_DERIVE_PARAMS) ============================

    [Fact]
    public void Ecdh1_RoundTrips_PublicPointAndSharedData()
    {
        byte[] point = [0x04, 1, 2, 3, 4];
        byte[] shared = [0x09, 0x08];
        var p = new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, point, shared);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_ECDH1_DERIVE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKD.CKD_SHA256_KDF, (ulong)s.Kdf);
        Assert.Equal((ulong)point.Length, (ulong)s.PublicDataLen);
        Assert.Equal(point, UnmanagedMemory.Read(s.PublicData, point.Length));
        Assert.Equal((ulong)shared.Length, (ulong)s.SharedDataLen);
        Assert.Equal(shared, UnmanagedMemory.Read(s.SharedData, shared.Length));
    }

    [Fact]
    public void Ecdh1_NoSharedData_NullPointerZeroLen()
    {
        byte[] point = [0x04, 9, 9];
        var p = new CkmEcdh1DeriveParams(CKD.CKD_NULL, point);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_ECDH1_DERIVE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(0UL, (ulong)s.SharedDataLen);
        Assert.Equal(IntPtr.Zero, s.SharedData);
    }

    [Fact]
    public void Ecdh1_RejectsEmptyPoint() =>
        Assert.Throws<ArgumentException>(() => new CkmEcdh1DeriveParams(CKD.CKD_NULL, default));

    // === EdDSA (CK_EDDSA_PARAMS) =========================================

    [Fact]
    public void Eddsa_RoundTrips_PhFlagAndContext()
    {
        byte[] ctx = [0x01, 0x02, 0x03];
        var p = new CkmEddsaParams(phFlag: true, ctx);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_EDDSA_PARAMS>(p.BuildMarshalable(scope));

        Assert.True(s.PhFlag);
        Assert.Equal((ulong)ctx.Length, (ulong)s.ContextDataLen);
        Assert.Equal(ctx, UnmanagedMemory.Read(s.ContextData, ctx.Length));
    }

    [Fact]
    public void Eddsa_NoContext_FalseFlagNullPointer()
    {
        var p = new CkmEddsaParams(phFlag: false);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_EDDSA_PARAMS>(p.BuildMarshalable(scope));

        Assert.False(s.PhFlag);
        Assert.Equal(0UL, (ulong)s.ContextDataLen);
        Assert.Equal(IntPtr.Zero, s.ContextData);
    }

    // === AES-CCM (CK_CCM_PARAMS) =========================================

    [Fact]
    public void AesCcm_RoundTrips_NonceAadLengths()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7];
        byte[] aad = [0xA1, 0xA2];
        var p = new CkmAesCcmParams(dataLen: 64, nonce, aad, macLen: 16);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_CCM_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(64UL, (ulong)s.DataLen);
        Assert.Equal((ulong)nonce.Length, (ulong)s.NonceLen);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.Equal((ulong)aad.Length, (ulong)s.AADLen);
        Assert.Equal(aad, UnmanagedMemory.Read(s.AAD, aad.Length));
        Assert.Equal(16UL, (ulong)s.MACLen);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(0)]
    [InlineData(18)]
    public void AesCcm_RejectsBadMacLen(int macLen) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new CkmAesCcmParams(64, new byte[7], default, macLen));

    [Fact]
    public void AesCcm_RejectsEmptyNonce() =>
        Assert.Throws<ArgumentException>(() => new CkmAesCcmParams(64, default, default, 16));

    // === ChaCha20 (CK_CHACHA20_PARAMS) ===================================

    [Fact]
    public void ChaCha20_RoundTrips_BlockCounterAndNonce()
    {
        byte[] blockCounter = [0, 0, 0, 1];
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        var p = new CkmChaCha20Params(blockCounter, blockCounterBits: 32, nonce, nonceBits: 96);
        using var scope = new MechanismParameterScope();
        var s = Marshalled<CK_CHACHA20_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(32UL, (ulong)s.BlockCounterBits);
        Assert.Equal(blockCounter, UnmanagedMemory.Read(s.BlockCounter, blockCounter.Length));
        Assert.Equal(96UL, (ulong)s.NonceBits);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
    }

    [Fact]
    public void ChaCha20_RejectsEmptyBlockCounter() =>
        Assert.Throws<ArgumentException>(() => new CkmChaCha20Params(default, 32, new byte[12], 96));

    [Fact]
    public void ChaCha20_RejectsEmptyNonce() =>
        Assert.Throws<ArgumentException>(() => new CkmChaCha20Params(new byte[4], 32, default, 96));
}
