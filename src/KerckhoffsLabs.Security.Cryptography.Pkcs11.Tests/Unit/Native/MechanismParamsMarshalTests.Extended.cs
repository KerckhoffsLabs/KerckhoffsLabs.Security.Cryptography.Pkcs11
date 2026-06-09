using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Shared round-trip helper for the mechanism-parameter marshal tests: writes the boxed low-level
/// <c>CK_*</c> struct through the platform marshaller and reads it back. Pointers in the result still
/// reference the wrapper's unmanaged buffers, so callers keep the wrapper alive while dereferencing.
/// </summary>
internal static class ParamMarshal
{
    public static T RoundTrip<T>(object raw) where T : struct
    {
        int size = UnmanagedMemory.SizeOf(typeof(T));
        IntPtr mem = UnmanagedMemory.Allocate(size);
        try
        {
            UnmanagedMemory.Write(mem, raw);
            return UnmanagedMemory.Read<T>(mem);
        }
        finally { UnmanagedMemory.Free(ref mem); }
    }
}

// === AEAD message-based params (CK_*_MESSAGE_PARAMS) ======================

public sealed class MechanismAeadMessageParamsTests
{
    [Fact]
    public void GcmMessage_ForEncrypt_MarshalsIvAndTagBits()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        using var p = CkmGcmMessageParams.ForEncrypt(iv, tagBytes: 16);
        var s = ParamMarshal.RoundTrip<CK_GCM_MESSAGE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)iv.Length, (ulong)s.IvLen);
        Assert.Equal(iv, UnmanagedMemory.Read(s.Iv, iv.Length));
        Assert.Equal(128UL, (ulong)s.TagBits); // 16 bytes
        Assert.NotEqual(IntPtr.Zero, s.Tag);    // pre-allocated output buffer
    }

    [Fact]
    public void GcmMessage_ForDecrypt_CopiesCallerTagBytes()
    {
        byte[] iv = [9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        byte[] tag = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        using var p = CkmGcmMessageParams.ForDecrypt(iv, tag);
        var s = ParamMarshal.RoundTrip<CK_GCM_MESSAGE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(tag, UnmanagedMemory.Read(s.Tag, tag.Length));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(17)]
    public void GcmMessage_RejectsBadTagLen(int tagBytes) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes));

    [Fact]
    public void GcmMessage_RejectsEmptyIv() =>
        Assert.Throws<ArgumentException>(() => CkmGcmMessageParams.ForEncrypt(default, 16));

    [Fact]
    public void CcmMessage_ForEncrypt_MarshalsNonceDataAndMacLen()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7]; // 7..13
        using var p = CkmCcmMessageParams.ForEncrypt(dataLen: 64, nonce, macBytes: 16);
        var s = ParamMarshal.RoundTrip<CK_CCM_MESSAGE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(64UL, (ulong)s.DataLen);
        Assert.Equal((ulong)nonce.Length, (ulong)s.NonceLen);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.Equal(16UL, (ulong)s.MacLen);
        Assert.NotEqual(IntPtr.Zero, s.Mac);
    }

    [Fact]
    public void CcmMessage_ForDecrypt_CopiesCallerMacBytes()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] mac = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
        using var p = CkmCcmMessageParams.ForDecrypt(dataLen: 32, nonce, mac);
        var s = ParamMarshal.RoundTrip<CK_CCM_MESSAGE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)mac.Length, (ulong)s.MacLen);
        Assert.Equal(mac, UnmanagedMemory.Read(s.Mac, mac.Length));
    }

    [Theory]
    [InlineData(6)]  // below 7
    [InlineData(14)] // above 13
    public void CcmMessage_RejectsBadNonceLength(int nonceLen) =>
        Assert.Throws<ArgumentException>(() => CkmCcmMessageParams.ForEncrypt(32, new byte[nonceLen], 16));

    [Theory]
    [InlineData(5)]
    [InlineData(18)]
    public void CcmMessage_RejectsBadMacLen(int macBytes) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => CkmCcmMessageParams.ForEncrypt(32, new byte[8], macBytes));

    [Fact]
    public void SalsaChaChaPoly1305Message_ForEncrypt_MarshalsNonce()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        using var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForEncrypt(nonce);
        var s = ParamMarshal.RoundTrip<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)nonce.Length, (ulong)s.NonceLen);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.NotEqual(IntPtr.Zero, s.Tag);
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_ForDecrypt_CopiesTag()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] tag = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        using var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(nonce, tag);
        var s = ParamMarshal.RoundTrip<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(tag, UnmanagedMemory.Read(s.Tag, tag.Length));
    }

    [Fact]
    public void SalsaChaChaPoly1305Message_ForDecrypt_RejectsNon16ByteTag() =>
        Assert.Throws<ArgumentException>(() => CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(new byte[12], new byte[15]));
}

// === Stream / AEAD nonce params ==========================================

public sealed class MechanismStreamParamsTests
{
    [Fact]
    public void Salsa20_MarshalsBlockCounterAndNonce()
    {
        byte[] blockCounter = [0, 0, 0, 0, 0, 0, 0, 1];
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        using var p = new CkmSalsa20Params(blockCounter, nonce, nonceBits: 64);
        var s = ParamMarshal.RoundTrip<CK_SALSA20_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(blockCounter, UnmanagedMemory.Read(s.BlockCounter, blockCounter.Length));
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.Equal(64UL, (ulong)s.NonceBits);
    }

    [Fact]
    public void Salsa20_RejectsEmptyBlockCounter() =>
        Assert.Throws<ArgumentException>(() => new CkmSalsa20Params(default, new byte[8], 64));

    [Fact]
    public void Salsa20_RejectsEmptyNonce() =>
        Assert.Throws<ArgumentException>(() => new CkmSalsa20Params(new byte[8], default, 64));

    [Fact]
    public void SalsaChaChaPoly1305_MarshalsNonceAndAad()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] aad = [0xAA, 0xBB];
        using var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        var s = ParamMarshal.RoundTrip<CK_SALSA20_CHACHA20_POLY1305_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)nonce.Length, (ulong)s.NonceLen);
        Assert.Equal(nonce, UnmanagedMemory.Read(s.Nonce, nonce.Length));
        Assert.Equal((ulong)aad.Length, (ulong)s.AADLen);
        Assert.Equal(aad, UnmanagedMemory.Read(s.AAD, aad.Length));
    }

    [Fact]
    public void SalsaChaChaPoly1305_EmptyAad_NullPointer()
    {
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        using var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, default);
        var s = ParamMarshal.RoundTrip<CK_SALSA20_CHACHA20_POLY1305_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(0UL, (ulong)s.AADLen);
        Assert.Equal(IntPtr.Zero, s.AAD);
    }

    [Fact]
    public void SalsaChaChaPoly1305_RejectsEmptyNonce() =>
        Assert.Throws<ArgumentException>(() => new CkmSalsa20ChaCha20Poly1305Params(default, default));
}

// === KDF params (HKDF, SP800-108 KDF / feedback) =========================

public sealed class MechanismKdfParamsTests
{
    [Fact]
    public void Hkdf_MarshalsSaltInfoAndFlags()
    {
        byte[] salt = [1, 2, 3, 4];
        byte[] info = [9, 8, 7];
        using var p = new CkmHkdfParams(extract: true, expand: true, CKM.CKM_SHA256_HMAC,
            saltType: 1, salt, saltKey: 0, info);
        var s = ParamMarshal.RoundTrip<CK_HKDF_PARAMS>(p.ToMarshalableStructure());

        Assert.True(s.Extract);
        Assert.True(s.Expand);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfHashMechanism);
        Assert.Equal(1UL, (ulong)s.SaltType);
        Assert.Equal((ulong)salt.Length, (ulong)s.SaltLen);
        Assert.Equal(salt, UnmanagedMemory.Read(s.Salt, salt.Length));
        Assert.Equal((ulong)info.Length, (ulong)s.InfoLen);
        Assert.Equal(info, UnmanagedMemory.Read(s.Info, info.Length));
    }

    [Fact]
    public void Hkdf_EmptySaltAndInfo_NullPointersFalseFlags()
    {
        using var p = new CkmHkdfParams(extract: false, expand: false, CKM.CKM_SHA256_HMAC,
            saltType: 0, default, saltKey: 0, default);
        var s = ParamMarshal.RoundTrip<CK_HKDF_PARAMS>(p.ToMarshalableStructure());

        Assert.False(s.Extract);
        Assert.False(s.Expand);
        Assert.Equal(IntPtr.Zero, s.Salt);
        Assert.Equal(0UL, (ulong)s.SaltLen);
        Assert.Equal(IntPtr.Zero, s.Info);
        Assert.Equal(0UL, (ulong)s.InfoLen);
    }

    [Fact]
    public void Sp800108Kdf_MarshalsPrfAndDataParamCount()
    {
        using var p = new CkmSp800108KdfParams(CKM.CKM_SHA256_HMAC, dataParams: IntPtr.Zero, numberOfDataParams: 5);
        var s = ParamMarshal.RoundTrip<CK_SP800_108_KDF_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfType);
        Assert.Equal(5UL, (ulong)s.NumberOfDataParams);
    }

    [Fact]
    public void Sp800108FeedbackKdf_MarshalsIvAndPrf()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8];
        using var p = new CkmSp800108FeedbackKdfParams(CKM.CKM_SHA256_HMAC, dataParams: IntPtr.Zero,
            numberOfDataParams: 3, iv);
        var s = ParamMarshal.RoundTrip<CK_SP800_108_FEEDBACK_KDF_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfType);
        Assert.Equal(3UL, (ulong)s.NumberOfDataParams);
        Assert.Equal((ulong)iv.Length, (ulong)s.IVLen);
        Assert.Equal(iv, UnmanagedMemory.Read(s.IV, iv.Length));
    }

    [Fact]
    public void Sp800108FeedbackKdf_EmptyIv_NullPointer()
    {
        using var p = new CkmSp800108FeedbackKdfParams(CKM.CKM_SHA256_HMAC, IntPtr.Zero, 3, default);
        var s = ParamMarshal.RoundTrip<CK_SP800_108_FEEDBACK_KDF_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(0UL, (ulong)s.IVLen);
        Assert.Equal(IntPtr.Zero, s.IV);
    }
}

// === PQC sign / XEdDSA params ============================================

public sealed class MechanismPqcSignParamsTests
{
    [Fact]
    public void PqcSign_MarshalsHedgeAndContext()
    {
        byte[] context = [0x01, 0x02, 0x03];
        using var p = new CkmPqcSignParams(CkhHedge.CKH_HEDGE_REQUIRED, context);
        var s = ParamMarshal.RoundTrip<CK_SIGN_ADDITIONAL_CONTEXT>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CkhHedge.CKH_HEDGE_REQUIRED, (ulong)s.HedgeVariant);
        Assert.Equal((ulong)context.Length, (ulong)s.ContextLen);
        Assert.Equal(context, UnmanagedMemory.Read(s.Context, context.Length));
    }

    [Fact]
    public void PqcSign_DefaultHedge_EmptyContext_NullPointer()
    {
        using var p = new CkmPqcSignParams();
        var s = ParamMarshal.RoundTrip<CK_SIGN_ADDITIONAL_CONTEXT>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CkhHedge.CKH_HEDGE_PREFERRED, (ulong)s.HedgeVariant);
        Assert.Equal(0UL, (ulong)s.ContextLen);
        Assert.Equal(IntPtr.Zero, s.Context);
    }

    [Fact]
    public void PqcSign_RejectsContextOver255Bytes() =>
        Assert.Throws<ArgumentException>(() => new CkmPqcSignParams(CkhHedge.CKH_HEDGE_PREFERRED, new byte[256]));

    [Fact]
    public void HashPqcSign_MarshalsHashHedgeAndContext()
    {
        byte[] context = [0xAA];
        using var p = new CkmHashPqcSignParams(CKM.CKM_SHA256, CkhHedge.CKH_HEDGE_REQUIRED, context);
        var s = ParamMarshal.RoundTrip<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CKM.CKM_SHA256, (ulong)s.Hash);
        Assert.Equal((ulong)CkhHedge.CKH_HEDGE_REQUIRED, (ulong)s.HedgeVariant);
        Assert.Equal((ulong)context.Length, (ulong)s.ContextLen);
        Assert.Equal(context, UnmanagedMemory.Read(s.Context, context.Length));
    }

    [Fact]
    public void HashPqcSign_RejectsContextOver255Bytes() =>
        Assert.Throws<ArgumentException>(() => new CkmHashPqcSignParams(CKM.CKM_SHA256, context: new byte[256]));

    [Fact]
    public void Xeddsa_MarshalsHashType()
    {
        using var p = new CkmXeddsaParams(hashType: (ulong)CKM.CKM_SHA512);
        var s = ParamMarshal.RoundTrip<CK_XEDDSA_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CKM.CKM_SHA512, (ulong)s.Hash);
    }
}

// === IKE derive params ===================================================

public sealed class MechanismIkeDeriveParamsTests
{
    [Fact]
    public void IkePrfDerive_MarshalsNoncesFlagsAndKey()
    {
        byte[] ni = [1, 2, 3];
        byte[] nr = [4, 5];
        using var p = new CkmIkePrfDeriveParams(CKM.CKM_SHA256_HMAC, dataAsKey: true, rekey: false, ni, nr, newKey: 7);
        var s = ParamMarshal.RoundTrip<CK_IKE_PRF_DERIVE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.True(s.DataAsKey);
        Assert.False(s.Rekey);
        Assert.Equal(ni, UnmanagedMemory.Read(s.Ni, ni.Length));
        Assert.Equal(nr, UnmanagedMemory.Read(s.Nr, nr.Length));
        Assert.Equal(7UL, (ulong)s.NewKey);
    }

    [Fact]
    public void Ike1PrfDerive_MarshalsCookiesFlagAndKeyNumber()
    {
        byte[] ckyI = [0x11, 0x22];
        byte[] ckyR = [0x33];
        using var p = new CkmIke1PrfDeriveParams(CKM.CKM_SHA256_HMAC, hasPrevKey: true,
            keygxy: 1, prevKey: 2, ckyI, ckyR, keyNumber: 9);
        var s = ParamMarshal.RoundTrip<CK_IKE1_PRF_DERIVE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.True(s.HasPrevKey);
        Assert.Equal(ckyI, UnmanagedMemory.Read(s.CkyI, ckyI.Length));
        Assert.Equal(ckyR, UnmanagedMemory.Read(s.CkyR, ckyR.Length));
        Assert.Equal((byte)9, s.KeyNumber);
    }

    [Fact]
    public void Ike1ExtendedDerive_MarshalsFlagAndExtraData()
    {
        byte[] extra = [0xDE, 0xAD];
        using var p = new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, hasKeygxy: true, keygxy: 5, extra);
        var s = ParamMarshal.RoundTrip<CK_IKE1_EXTENDED_DERIVE_PARAMS>(p.ToMarshalableStructure());

        Assert.True(s.HasKeygxy);
        Assert.Equal(5UL, (ulong)s.Keygxy);
        Assert.Equal((ulong)extra.Length, (ulong)s.ExtraDataLen);
        Assert.Equal(extra, UnmanagedMemory.Read(s.ExtraData, extra.Length));
    }

    [Fact]
    public void Ike2PrfPlusDerive_MarshalsFlagAndSeedData()
    {
        byte[] seed = [0xBE, 0xEF, 0x01];
        using var p = new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, hasSeedKey: false, seedKey: 0, seed);
        var s = ParamMarshal.RoundTrip<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>(p.ToMarshalableStructure());

        Assert.False(s.HasSeedKey);
        Assert.Equal((ulong)seed.Length, (ulong)s.SeedDataLen);
        Assert.Equal(seed, UnmanagedMemory.Read(s.SeedData, seed.Length));
    }
}

// === Base MechanismParameters lifecycle ==================================

public sealed class MechanismParamsLifecycleTests
{
    [Fact]
    public void DoubleDispose_IsSafe()
    {
        var p = new CkmAesGcmParams([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], default, 128);
        p.Dispose();
        Assert.Null(Record.Exception(p.Dispose)); // must not throw or double-free
    }

    [Fact]
    public void ToMarshalableStructure_AfterDispose_Throws()
    {
        var p = new CkmAesGcmParams([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], default, 128);
        p.Dispose();
        Assert.Throws<ObjectDisposedException>(() => p.ToMarshalableStructure());
    }
}

// === Signal-protocol params (X3DH / Double Ratchet) ======================

public sealed class MechanismSignalParamsTests
{
    [Fact]
    public void X3dhInitiate_MarshalsHandlesAndKeyBytes()
    {
        byte[] sig = [1, 2, 3];
        byte[] otk = [4, 5];
        using var p = new CkmX3dhInitiateParams(kdf: 1, peerIdentity: 2, peerPrekey: 3, sig, otk, ownIdentity: 4, ownEphemeral: 5);
        var s = ParamMarshal.RoundTrip<CK_X3DH_INITIATE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(1UL, (ulong)s.Kdf);
        Assert.Equal(2UL, (ulong)s.PeerIdentity);
        Assert.Equal(3UL, (ulong)s.PeerPrekey);
        Assert.Equal(4UL, (ulong)s.OwnIdentity);
        Assert.Equal(5UL, (ulong)s.OwnEphemeral);
        Assert.Equal(sig, UnmanagedMemory.Read(s.PrekeySignature, sig.Length));
        Assert.Equal(otk, UnmanagedMemory.Read(s.OnetimeKey, otk.Length));
    }

    [Fact]
    public void X3dhRespond_MarshalsHandlesAndIdBytes()
    {
        byte[] id = [0x11];
        byte[] pre = [0x22, 0x23];
        byte[] otp = [0x33];
        byte[] eph = [0x44, 0x45, 0x46];
        using var p = new CkmX3dhRespondParams(kdf: 7, id, pre, otp, initiatorIdentity: 8, eph);
        var s = ParamMarshal.RoundTrip<CK_X3DH_RESPOND_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(7UL, (ulong)s.Kdf);
        Assert.Equal(8UL, (ulong)s.InitiatorIdentity);
        Assert.Equal(id, UnmanagedMemory.Read(s.IdentityId, id.Length));
        Assert.Equal(pre, UnmanagedMemory.Read(s.PrekeyId, pre.Length));
        Assert.Equal(otp, UnmanagedMemory.Read(s.OnetimeId, otp.Length));
        Assert.Equal(eph, UnmanagedMemory.Read(s.InitiatorEphemeral, eph.Length));
    }

    [Fact]
    public void X2RatchetInitialize_MarshalsSecretFlagsAndMechanisms()
    {
        byte[] sk = [1, 2, 3, 4, 5, 6, 7, 8];
        using var p = new CkmX2RatchetInitializeParams(sk, peerPublicPrekey: 1, peerPublicIdentity: 2,
            ownPublicIdentity: 3, encryptedHeader: true, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 5);
        var s = ParamMarshal.RoundTrip<CK_X2RATCHET_INITIALIZE_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(sk, UnmanagedMemory.Read(s.Sk, sk.Length));
        Assert.Equal(1UL, (ulong)s.PeerPublicPrekey);
        Assert.Equal(2UL, (ulong)s.PeerPublicIdentity);
        Assert.Equal(3UL, (ulong)s.OwnPublicIdentity);
        Assert.True(s.EncryptedHeader);
        Assert.Equal(4UL, (ulong)s.Curve);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, (ulong)s.AeadMechanism);
        Assert.Equal(5UL, (ulong)s.KdfMechanism);
    }

    [Fact]
    public void X2RatchetInitialize_RejectsEmptySharedSecret() =>
        Assert.Throws<ArgumentException>(() => new CkmX2RatchetInitializeParams(default, 1, 2, 3, false, 4, CKM.CKM_AES_GCM, 5));

    [Fact]
    public void X2RatchetRespond_MarshalsSecretFlagsAndMechanisms()
    {
        byte[] sk = [9, 8, 7, 6];
        using var p = new CkmX2RatchetRespondParams(sk, ownPrekey: 1, initiatorIdentity: 2,
            ownPublicIdentity: 3, encryptedHeader: false, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 6);
        var s = ParamMarshal.RoundTrip<CK_X2RATCHET_RESPOND_PARAMS>(p.ToMarshalableStructure());

        Assert.Equal(sk, UnmanagedMemory.Read(s.Sk, sk.Length));
        Assert.Equal(1UL, (ulong)s.OwnPrekey);
        Assert.Equal(2UL, (ulong)s.InitiatorIdentity);
        Assert.Equal(3UL, (ulong)s.OwnPublicIdentity);
        Assert.False(s.EncryptedHeader);
        Assert.Equal(4UL, (ulong)s.Curve);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, (ulong)s.AeadMechanism);
        Assert.Equal(6UL, (ulong)s.KdfMechanism);
    }

    [Fact]
    public void X2RatchetRespond_RejectsEmptySharedSecret() =>
        Assert.Throws<ArgumentException>(() => new CkmX2RatchetRespondParams(default, 1, 2, 3, false, 4, CKM.CKM_AES_GCM, 6));
}
