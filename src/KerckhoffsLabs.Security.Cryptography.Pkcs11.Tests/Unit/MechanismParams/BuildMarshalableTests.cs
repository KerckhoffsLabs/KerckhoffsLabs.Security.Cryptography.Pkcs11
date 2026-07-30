using System.Buffers.Binary;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// Field-by-field coverage of what <c>BuildMarshalable</c> writes into a call scope: every scalar
/// against the literal its fixture passed in, and every pointer field read back for the bytes it must
/// address. The fixtures are deliberately non-degenerate — distinct values, no zeros where a zero
/// could pass by accident — so a dropped or mistyped assignment cannot slip through.
/// </summary>
public sealed class BuildMarshalableTests
{
    // CK_PRF_DATA_TYPE tags (OASIS pkcs11t.h).
    private const ulong IterationVariable = 1, OptionalCounter = 2, DkmLengthTag = 3, ByteArrayTag = 4, KeyHandleTag = 5;

    [Fact]
    public void EddsaParams_MarshalsItsFields()
    {
        using var p = new CkmEddsaParams(phFlag: true, [0xAA, 0xBB, 0xCC]);
        using var scope = new MechanismParameterScope();

        var s = (CK_EDDSA_PARAMS)p.BuildMarshalable(scope);

        Assert.True(s.PhFlag);
        Assert.Equal(3UL, (ulong)s.ContextDataLen);
        AssertBlockHolds(s.ContextData, [0xAA, 0xBB, 0xCC]);
    }

    [Fact]
    public void Rc2Params_MarshalsItsFields()
    {
        using var p = new CkmRc2Params(128);
        using var scope = new MechanismParameterScope();

        var s = (CK_RC2_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(128UL, (ulong)s.EffectiveBits);
    }

    [Fact]
    public void EmptyBuffer_MarshalsAsNullPointer()
    {
        using var p = new CkmEddsaParams(phFlag: false, default);
        using var scope = new MechanismParameterScope();

        var s = (CK_EDDSA_PARAMS)p.BuildMarshalable(scope);

        Assert.False(s.PhFlag);
        Assert.Equal(IntPtr.Zero, s.ContextData);
        Assert.Equal(0UL, (ulong)s.ContextDataLen);
    }

    // ---------------------------------------------------------------------------------------------
    // The allocation-free types: their structs carry no pointer, so the scalars are the whole test.
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void Rc2CbcParams_MarshalsItsFields()
    {
        byte[] iv = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        using var p = new CkmRc2CbcParams(128, iv);
        using var scope = new MechanismParameterScope();

        var s = (CK_RC2_CBC_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(128UL, (ulong)s.EffectiveBits);
        // Iv is an inline CkChar8 buffer, not a pointer, so the bytes travel inside the struct.
        Assert.True(iv.AsSpan().SequenceEqual(s.Iv));
    }

    [Fact]
    public void RsaPkcsPssParams_MarshalsItsFields()
    {
        using var p = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var scope = new MechanismParameterScope();

        var s = (CK_RSA_PKCS_PSS_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKM.CKM_SHA256, (ulong)s.HashAlg);
        Assert.Equal((ulong)CKG.CKG_MGF1_SHA256, (ulong)s.Mgf);
        Assert.Equal(32UL, (ulong)s.Len);
    }

    [Fact]
    public void XeddsaParams_MarshalsItsFields()
    {
        using var p = new CkmXeddsaParams(hashType: 1);
        using var scope = new MechanismParameterScope();

        var s = (CK_XEDDSA_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(1UL, (ulong)s.Hash);
    }

    // ---------------------------------------------------------------------------------------------
    // The single-buffer types: every scalar against its literal, and the pointer must address a block
    // holding the fixture's bytes.
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void HashPqcSignParams_MarshalsItsFields()
    {
        using var p = new CkmHashPqcSignParams(CKM.CKM_SHA256, CkhHedge.CKH_HEDGE_REQUIRED, [0x01, 0x02]);
        using var scope = new MechanismParameterScope();

        var s = (CK_HASH_SIGN_ADDITIONAL_CONTEXT)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CkhHedge.CKH_HEDGE_REQUIRED, (ulong)s.HedgeVariant);
        Assert.Equal((ulong)CKM.CKM_SHA256, (ulong)s.Hash);
        Assert.Equal(2UL, (ulong)s.ContextLen);
        AssertBlockHolds(s.Context, [0x01, 0x02]);
    }

    [Fact]
    public void Ike1ExtendedDeriveParams_MarshalsItsFields()
    {
        using var p = new CkmIke1ExtendedDeriveParams(
            CKM.CKM_SHA256_HMAC, hasKeygxy: true, keygxy: 5, [0xE1, 0xE2]);
        using var scope = new MechanismParameterScope();

        var s = (CK_IKE1_EXTENDED_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.True(s.HasKeygxy);
        Assert.Equal(5UL, (ulong)s.Keygxy);
        Assert.Equal(2UL, (ulong)s.ExtraDataLen);
        AssertBlockHolds(s.ExtraData, [0xE1, 0xE2]);
    }

    [Fact]
    public void Ike2PrfPlusDeriveParams_MarshalsItsFields()
    {
        using var p = new CkmIke2PrfPlusDeriveParams(
            CKM.CKM_SHA256_HMAC, hasSeedKey: true, seedKey: 7, [0x5E, 0x5D, 0x5C]);
        using var scope = new MechanismParameterScope();

        var s = (CK_IKE2_PRF_PLUS_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.True(s.HasSeedKey);
        Assert.Equal(7UL, (ulong)s.SeedKey);
        Assert.Equal(3UL, (ulong)s.SeedDataLen);
        AssertBlockHolds(s.SeedData, [0x5E, 0x5D, 0x5C]);
    }

    [Fact]
    public void PqcSignParams_MarshalsItsFields()
    {
        using var p = new CkmPqcSignParams(CkhHedge.CKH_HEDGE_REQUIRED, [0xC0, 0xC1, 0xC2]);
        using var scope = new MechanismParameterScope();

        var s = (CK_SIGN_ADDITIONAL_CONTEXT)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CkhHedge.CKH_HEDGE_REQUIRED, (ulong)s.HedgeVariant);
        Assert.Equal(3UL, (ulong)s.ContextLen);
        AssertBlockHolds(s.Context, [0xC0, 0xC1, 0xC2]);
    }

    [Fact]
    public void RsaPkcsOaepParams_MarshalsItsFields()
    {
        using var p = new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, [0x0A, 0x0B]);
        using var scope = new MechanismParameterScope();

        var s = (CK_RSA_PKCS_OAEP_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKM.CKM_SHA256, (ulong)s.HashAlg);
        Assert.Equal((ulong)CKG.CKG_MGF1_SHA256, (ulong)s.Mgf);
        // Hardcoded, not caller-supplied: a change here would mean the struct stopped declaring that
        // the source data is present, and the token would ignore the buffer.
        Assert.Equal((ulong)CKZ.CKZ_DATA_SPECIFIED, (ulong)s.Source);
        Assert.Equal(2UL, (ulong)s.SourceDataLen);
        AssertBlockHolds(s.SourceData, [0x0A, 0x0B]);
    }

    [Fact]
    public void X2RatchetInitializeParams_MarshalsItsFields()
    {
        byte[] sk = [0x51, 0x52, 0x53, 0x54];
        using var p = new CkmX2RatchetInitializeParams(
            sk, peerPublicPrekey: 1, peerPublicIdentity: 2, ownPublicIdentity: 3,
            encryptedHeader: true, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 5);
        using var scope = new MechanismParameterScope();

        var s = (CK_X2RATCHET_INITIALIZE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(1UL, (ulong)s.PeerPublicPrekey);
        Assert.Equal(2UL, (ulong)s.PeerPublicIdentity);
        Assert.Equal(3UL, (ulong)s.OwnPublicIdentity);
        Assert.True(s.EncryptedHeader);
        Assert.Equal(4UL, (ulong)s.Curve);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, (ulong)s.AeadMechanism);
        Assert.Equal(5UL, (ulong)s.KdfMechanism);
        AssertBlockHolds(s.Sk, sk);
    }

    [Fact]
    public void X2RatchetRespondParams_MarshalsItsFields()
    {
        byte[] sk = [0x61, 0x62, 0x63, 0x64];
        using var p = new CkmX2RatchetRespondParams(
            sk, ownPrekey: 1, initiatorIdentity: 2, ownPublicIdentity: 3,
            encryptedHeader: false, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 6);
        using var scope = new MechanismParameterScope();

        var s = (CK_X2RATCHET_RESPOND_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(1UL, (ulong)s.OwnPrekey);
        Assert.Equal(2UL, (ulong)s.InitiatorIdentity);
        Assert.Equal(3UL, (ulong)s.OwnPublicIdentity);
        Assert.False(s.EncryptedHeader);
        Assert.Equal(4UL, (ulong)s.Curve);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, (ulong)s.AeadMechanism);
        Assert.Equal(6UL, (ulong)s.KdfMechanism);
        AssertBlockHolds(s.Sk, sk);
    }

    // ---------------------------------------------------------------------------------------------
    // The multi-buffer types: every scalar against its literal, and each pointer read back separately
    // so a swapped pair cannot pass.
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void AesGcmParams_MarshalsItsFields()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] aad = [0xA0, 0xA1];
        using var p = new CkmAesGcmParams(iv, aad, tagBits: 128);
        using var scope = new MechanismParameterScope();

        var s = (CK_GCM_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(12UL, (ulong)s.IvLen);
        Assert.Equal(2UL, (ulong)s.AADLen);
        Assert.Equal(128UL, (ulong)s.TagBits);
        // Deliberately 0: the IV length travels in IvLen, and some tokens reject a non-zero IvBits.
        Assert.Equal(0UL, (ulong)s.IvBits);
        AssertBlockHolds(s.Iv, iv);
        AssertBlockHolds(s.AAD, aad);
    }

    [Fact]
    public void AesGcmParams_EmptyAad_MarshalsAsNullPointer()
    {
        using var p = new CkmAesGcmParams(new byte[12], default, tagBits: 128);
        using var scope = new MechanismParameterScope();

        var s = (CK_GCM_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(IntPtr.Zero, s.AAD);
        Assert.Equal(0UL, (ulong)s.AADLen);
    }

    [Fact]
    public void AesCcmParams_MarshalsItsFields()
    {
        byte[] nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        byte[] aad = [0xAA, 0xBB, 0xCC];
        using var p = new CkmAesCcmParams(dataLen: 64, nonce, aad, macLen: 16);
        using var scope = new MechanismParameterScope();

        var s = (CK_CCM_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(64UL, (ulong)s.DataLen);
        Assert.Equal(7UL, (ulong)s.NonceLen);
        Assert.Equal(3UL, (ulong)s.AADLen);
        Assert.Equal(16UL, (ulong)s.MACLen);
        AssertBlockHolds(s.Nonce, nonce);
        AssertBlockHolds(s.AAD, aad);
    }

    [Fact]
    public void ChaCha20Params_MarshalsItsFields()
    {
        byte[] blockCounter = [0x01, 0x00, 0x00, 0x00];
        byte[] nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        using var p = new CkmChaCha20Params(blockCounter, blockCounterBits: 32, nonce, nonceBits: 96);
        using var scope = new MechanismParameterScope();

        var s = (CK_CHACHA20_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(32UL, (ulong)s.BlockCounterBits);
        Assert.Equal(96UL, (ulong)s.NonceBits);
        AssertBlockHolds(s.BlockCounter, blockCounter);
        AssertBlockHolds(s.Nonce, nonce);
    }

    [Fact]
    public void Ecdh1DeriveParams_MarshalsItsFields()
    {
        byte[] peerPublicPoint = [0x04, 0x01, 0x02, 0x03, 0x04, 0x05];
        byte[] sharedData = [0x77, 0x78, 0x79];
        using var p = new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, peerPublicPoint, sharedData);
        using var scope = new MechanismParameterScope();

        var s = (CK_ECDH1_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKD.CKD_SHA256_KDF, (ulong)s.Kdf);
        Assert.Equal(3UL, (ulong)s.SharedDataLen);
        Assert.Equal(6UL, (ulong)s.PublicDataLen);
        AssertBlockHolds(s.PublicData, peerPublicPoint);
        AssertBlockHolds(s.SharedData, sharedData);
    }

    [Fact]
    public void HkdfParams_MarshalsItsFields()
    {
        byte[] salt = [0x01, 0x02, 0x03];
        byte[] info = [0xF0, 0xF1, 0xF2, 0xF3];
        using var p = new CkmHkdfParams(
            extract: true, expand: true, CKM.CKM_SHA256_HMAC, saltType: 2, salt, saltKey: 9, info);
        using var scope = new MechanismParameterScope();

        var s = (CK_HKDF_PARAMS)p.BuildMarshalable(scope);

        Assert.True(s.Extract);
        Assert.True(s.Expand);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfHashMechanism);
        Assert.Equal(2UL, (ulong)s.SaltType);
        Assert.Equal(3UL, (ulong)s.SaltLen);
        Assert.Equal(9UL, (ulong)s.SaltKey);
        Assert.Equal(4UL, (ulong)s.InfoLen);
        AssertBlockHolds(s.Salt, salt);
        AssertBlockHolds(s.Info, info);
    }

    [Fact]
    public void Ike1PrfDeriveParams_MarshalsItsFields()
    {
        byte[] ckyI = [0x01, 0x02, 0x03, 0x04];
        byte[] ckyR = [0x05, 0x06, 0x07, 0x08];
        using var p = new CkmIke1PrfDeriveParams(
            CKM.CKM_SHA256_HMAC, hasPrevKey: true, keygxy: 11, prevKey: 22, ckyI, ckyR, keyNumber: 3);
        using var scope = new MechanismParameterScope();

        var s = (CK_IKE1_PRF_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.True(s.HasPrevKey);
        Assert.Equal(11UL, (ulong)s.Keygxy);
        Assert.Equal(22UL, (ulong)s.PrevKey);
        Assert.Equal(4UL, (ulong)s.CkyILen);
        Assert.Equal(4UL, (ulong)s.CkyRLen);
        Assert.Equal((byte)3, s.KeyNumber);
        AssertBlockHolds(s.CkyI, ckyI);
        AssertBlockHolds(s.CkyR, ckyR);
    }

    [Fact]
    public void IkePrfDeriveParams_MarshalsItsFields()
    {
        byte[] ni = [0x21, 0x22, 0x23];
        byte[] nr = [0x31, 0x32, 0x33, 0x34];
        using var p = new CkmIkePrfDeriveParams(
            CKM.CKM_SHA256_HMAC, dataAsKey: true, rekey: true, ni, nr, newKey: 42);
        using var scope = new MechanismParameterScope();

        var s = (CK_IKE_PRF_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.True(s.DataAsKey);
        Assert.True(s.Rekey);
        Assert.Equal(3UL, (ulong)s.NiLen);
        Assert.Equal(4UL, (ulong)s.NrLen);
        Assert.Equal(42UL, (ulong)s.NewKey);
        AssertBlockHolds(s.Ni, ni);
        AssertBlockHolds(s.Nr, nr);
    }

    [Fact]
    public void Salsa20Params_MarshalsItsFields()
    {
        byte[] blockCounter = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        byte[] nonce = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
        using var p = new CkmSalsa20Params(blockCounter, nonce, nonceBits: 64);
        using var scope = new MechanismParameterScope();

        var s = (CK_SALSA20_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(64UL, (ulong)s.NonceBits);
        AssertBlockHolds(s.BlockCounter, blockCounter);
        AssertBlockHolds(s.Nonce, nonce);
    }

    [Fact]
    public void Salsa20ChaCha20Poly1305Params_MarshalsItsFields()
    {
        byte[] nonce = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C];
        byte[] aad = [0x91, 0x92];
        using var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        using var scope = new MechanismParameterScope();

        var s = (CK_SALSA20_CHACHA20_POLY1305_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(12UL, (ulong)s.NonceLen);
        Assert.Equal(2UL, (ulong)s.AADLen);
        AssertBlockHolds(s.Nonce, nonce);
        AssertBlockHolds(s.AAD, aad);
    }

    [Fact]
    public void X3dhInitiateParams_MarshalsItsFields()
    {
        byte[] prekeySignature = [0x51, 0x52, 0x53, 0x54, 0x55];
        byte[] onetimeKey = [0x61, 0x62, 0x63];
        using var p = new CkmX3dhInitiateParams(
            kdf: 1, peerIdentity: 2, peerPrekey: 3, prekeySignature, onetimeKey, ownIdentity: 4, ownEphemeral: 5);
        using var scope = new MechanismParameterScope();

        var s = (CK_X3DH_INITIATE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(1UL, (ulong)s.Kdf);
        Assert.Equal(2UL, (ulong)s.PeerIdentity);
        Assert.Equal(3UL, (ulong)s.PeerPrekey);
        Assert.Equal(4UL, (ulong)s.OwnIdentity);
        Assert.Equal(5UL, (ulong)s.OwnEphemeral);
        AssertBlockHolds(s.PrekeySignature, prekeySignature);
        AssertBlockHolds(s.OnetimeKey, onetimeKey);
    }

    [Fact]
    public void X3dhRespondParams_MarshalsItsFields()
    {
        byte[] identityId = [0x71, 0x72];
        byte[] prekeyId = [0x81, 0x82, 0x83];
        byte[] onetimeId = [0x91, 0x92, 0x93, 0x94];
        byte[] initiatorEphemeral = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
        using var p = new CkmX3dhRespondParams(
            kdf: 6, identityId, prekeyId, onetimeId, initiatorIdentity: 7, initiatorEphemeral);
        using var scope = new MechanismParameterScope();

        var s = (CK_X3DH_RESPOND_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(6UL, (ulong)s.Kdf);
        Assert.Equal(7UL, (ulong)s.InitiatorIdentity);
        AssertBlockHolds(s.IdentityId, identityId);
        AssertBlockHolds(s.PrekeyId, prekeyId);
        AssertBlockHolds(s.OnetimeId, onetimeId);
        AssertBlockHolds(s.InitiatorEphemeral, initiatorEphemeral);
    }

    // ---------------------------------------------------------------------------------------------
    // The in/out AEAD message types: built ForDecrypt so the tag/MAC field carries caller-supplied,
    // non-zero bytes — an encrypt fixture's zero-filled output buffer wouldn't distinguish a dropped
    // scope.Write from a correct one.
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void GcmMessageParams_MarshalsItsFields()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] tag = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC];
        using var p = CkmGcmMessageParams.ForDecrypt(iv, tag);
        using var scope = new MechanismParameterScope();

        var s = (CK_GCM_MESSAGE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(12UL, (ulong)s.IvLen);
        // Hardcoded, not caller-supplied: both must stay 0 to keep declaring "caller-supplied IV",
        // since IV generation is not exposed yet.
        Assert.Equal(0UL, (ulong)s.IvFixedBits);
        Assert.Equal(0UL, (ulong)s.IvGenerator);
        Assert.Equal(104UL, (ulong)s.TagBits); // 13 bytes
        AssertBlockHolds(s.Iv, iv);
        AssertBlockHolds(s.Tag, tag);
    }

    [Fact]
    public void CcmMessageParams_MarshalsItsFields()
    {
        byte[] nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
        byte[] mac = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB];
        using var p = CkmCcmMessageParams.ForDecrypt(dataLen: 48, nonce, mac);
        using var scope = new MechanismParameterScope();

        var s = (CK_CCM_MESSAGE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(48UL, (ulong)s.DataLen);
        Assert.Equal(9UL, (ulong)s.NonceLen);
        // Hardcoded, not caller-supplied: both must stay 0 to keep declaring "caller-supplied nonce",
        // since nonce generation is not exposed yet.
        Assert.Equal(0UL, (ulong)s.NonceFixedBits);
        Assert.Equal(0UL, (ulong)s.NonceGenerator);
        Assert.Equal(12UL, (ulong)s.MacLen);
        AssertBlockHolds(s.Nonce, nonce);
        AssertBlockHolds(s.Mac, mac);
    }

    [Fact]
    public void Salsa20ChaCha20Poly1305MsgParams_MarshalsItsFields()
    {
        byte[] nonce = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C];
        byte[] tag = [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF];
        using var p = CkmSalsa20ChaCha20Poly1305MsgParams.ForDecrypt(nonce, tag);
        using var scope = new MechanismParameterScope();

        var s = (CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(12UL, (ulong)s.NonceLen);
        AssertBlockHolds(s.Nonce, nonce);
        AssertBlockHolds(s.Tag, tag);
    }

    /// <summary>
    /// The SP800-108 graph is the deepest one: the top-level struct points at a
    /// <c>CK_PRF_DATA_PARAM</c> array whose entries point at format sub-structs, and at a
    /// <c>CK_DERIVED_KEY</c> array whose entries point at attribute templates and handle slots. Every
    /// level is walked, because a dropped inner allocation shows up nowhere in the scalar fields.
    /// </summary>
    [Fact]
    public void Sp800108CounterKdfParams_MarshalsItsFields()
    {
        byte[] label = [0x6C, 0x61, 0x62, 0x65, 0x6C];
        var template = new List<ObjectAttribute> { new(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY), new(CKA.CKA_KEY_TYPE, CKK.CKK_AES) };
        try
        {
            using var p = CkmSp800108KdfParams.Counter(CKM.CKM_AES_CMAC)
                .IterationCounter(widthInBits: 16, littleEndian: true)
                .OptionalCounter(widthInBits: 8, littleEndian: false)
                .ByteArray(label)
                .DkmLength(Sp800108DkmLengthMethod.SumOfSegments, widthInBits: 64, littleEndian: true)
                .KeyHandle(0xABCD)
                .AddDerivedKey(template)
                .Build();
            using var scope = new MechanismParameterScope();

            var s = (CK_SP800_108_KDF_PARAMS)p.BuildMarshalable(scope);

            Assert.Equal((ulong)CKM.CKM_AES_CMAC, (ulong)s.PrfType);
            Assert.Equal(5UL, (ulong)s.NumberOfDataParams);
            Assert.Equal(1UL, (ulong)s.AdditionalDerivedKeys);

            AssertPrfSequence(s.DataParams, label, spliceKey: 0xABCD, optionalCounterLittleEndian: false);
            AssertDerivedKeyArray(s.AdditionalDerivedKeysPtr, template);
        }
        finally
        {
            foreach (var a in template) a.Dispose();
        }
    }

    [Fact]
    public void Sp800108FeedbackKdfParams_MarshalsItsFields()
    {
        byte[] label = [0x66, 0x62, 0x6B];
        byte[] iv = [0xD1, 0xD2, 0xD3, 0xD4];
        using var p = CkmSp800108KdfParams.Feedback(CKM.CKM_SHA384_HMAC)
            .IterationCounter(widthInBits: 16, littleEndian: true)
            .OptionalCounter(widthInBits: 8, littleEndian: true)
            .ByteArray(label)
            .DkmLength(Sp800108DkmLengthMethod.SumOfSegments, widthInBits: 64, littleEndian: true)
            .KeyHandle(0xABCD)
            .WithIV(iv)
            .Build();
        using var scope = new MechanismParameterScope();

        var s = (CK_SP800_108_FEEDBACK_KDF_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)CKM.CKM_SHA384_HMAC, (ulong)s.PrfType);
        Assert.Equal(5UL, (ulong)s.NumberOfDataParams);
        Assert.Equal(4UL, (ulong)s.IVLen);
        Assert.Equal(0UL, (ulong)s.AdditionalDerivedKeys);
        Assert.Equal(IntPtr.Zero, s.AdditionalDerivedKeysPtr);

        AssertBlockHolds(s.IV, iv);
        AssertPrfSequence(s.DataParams, label, spliceKey: 0xABCD);
    }

    /// <summary>
    /// Walks the <c>CK_PRF_DATA_PARAM</c> array entry by entry: each tag, each length, and the values
    /// every format sub-struct behind it must decode to. The fixture uses non-default widths
    /// throughout and mixes <c>littleEndian: true</c> with one <c>false</c> segment, so neither a
    /// dropped assignment landing on a zero-initialised field nor a hardcoded <c>true</c> can pass.
    /// </summary>
    private static void AssertPrfSequence(
        IntPtr array, byte[] label, ulong spliceKey,
        bool iterationCounterLittleEndian = true, bool optionalCounterLittleEndian = true)
    {
        Assert.NotEqual(IntPtr.Zero, array);

        int elem = UnmanagedMemory.SizeOf<CK_PRF_DATA_PARAM>();
        CK_PRF_DATA_PARAM Entry(int i) => UnmanagedMemory.Read<CK_PRF_DATA_PARAM>(array + (i * elem));

        int counterSize = UnmanagedMemory.SizeOf<CK_SP800_108_COUNTER_FORMAT>();

        // [0] iteration counter and [1] optional counter — CK_SP800_108_COUNTER_FORMAT.
        foreach ((int index, ulong tag, ulong width, bool littleEndian) in new[]
            {
                (0, IterationVariable, 16UL, iterationCounterLittleEndian),
                (1, OptionalCounter, 8UL, optionalCounterLittleEndian),
            })
        {
            var entry = Entry(index);
            Assert.Equal(tag, (ulong)entry.Type);
            Assert.Equal((ulong)counterSize, (ulong)entry.ValueLen);
            Assert.NotEqual(IntPtr.Zero, entry.Value);

            var format = UnmanagedMemory.Read<CK_SP800_108_COUNTER_FORMAT>(entry.Value);
            Assert.Equal(littleEndian, format.LittleEndian);
            Assert.Equal(width, (ulong)format.WidthInBits);
        }

        // [2] byte array.
        var bytes = Entry(2);
        Assert.Equal(ByteArrayTag, (ulong)bytes.Type);
        Assert.Equal((ulong)label.Length, (ulong)bytes.ValueLen);
        AssertBlockHolds(bytes.Value, label);

        // [3] DKM length — CK_SP800_108_DKM_LENGTH_FORMAT.
        var dkm = Entry(3);
        Assert.Equal(DkmLengthTag, (ulong)dkm.Type);
        Assert.Equal((ulong)UnmanagedMemory.SizeOf<CK_SP800_108_DKM_LENGTH_FORMAT>(), (ulong)dkm.ValueLen);
        var dkmFormat = UnmanagedMemory.Read<CK_SP800_108_DKM_LENGTH_FORMAT>(dkm.Value);
        Assert.Equal((ulong)Sp800108DkmLengthMethod.SumOfSegments, (ulong)dkmFormat.DkmLengthMethod);
        Assert.True(dkmFormat.LittleEndian);
        Assert.Equal(64UL, (ulong)dkmFormat.WidthInBits);

        // [4] key handle — the value block holds the spliced key's CK_OBJECT_HANDLE.
        var handle = Entry(4);
        Assert.Equal(KeyHandleTag, (ulong)handle.Type);
        Assert.Equal((ulong)UnmanagedMemory.NativeULongSize, (ulong)handle.ValueLen);
        Assert.Equal(spliceKey, ReadHandle(handle.Value));
    }

    /// <summary>
    /// Walks the <c>CK_DERIVED_KEY</c> array: the attribute template must carry the caller's
    /// attributes, and the handle slot must be a distinct zero-filled block for the token to write
    /// into.
    /// </summary>
    private static void AssertDerivedKeyArray(IntPtr array, IReadOnlyList<ObjectAttribute> template)
    {
        Assert.NotEqual(IntPtr.Zero, array);

        var entry = UnmanagedMemory.Read<CK_DERIVED_KEY>(array);
        Assert.Equal((ulong)template.Count, (ulong)entry.AttributeCount);
        Assert.NotEqual(IntPtr.Zero, entry.Template);
        Assert.NotEqual(IntPtr.Zero, entry.Key);

        // The slot itself — not just its address — starts zero-filled (CK_INVALID_HANDLE), because
        // MechanismParameterScope.Allocate zero-fills and nothing has written to it yet.
        Assert.Equal(0UL, ReadHandle(entry.Key));

        int attrSize = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        for (int k = 0; k < template.Count; k++)
        {
            var marshalled = UnmanagedMemory.Read<CK_ATTRIBUTE>(entry.Template + (k * attrSize));
            CK_ATTRIBUTE expected = template[k].CkAttribute;
            Assert.Equal((ulong)expected.type, (ulong)marshalled.type);
            Assert.Equal((ulong)expected.valueLen, (ulong)marshalled.valueLen);
            // The value buffer belongs to the caller's ObjectAttribute and is referenced, not copied.
            Assert.Equal(expected.value, marshalled.value);
        }
    }

    /// <summary>
    /// Sharing one descriptor across two mechanisms is now legal: each marshals into its own scope,
    /// so neither can free buffers the other addresses. This is the hazard that previously required
    /// a runtime guard.
    /// </summary>
    [Fact]
    public void OneDescriptor_CanBackTwoMechanisms()
    {
        using var p = new CkmAesGcmParams(new byte[12], [0xA0], tagBits: 128);
        using var first = new Mechanism(CKM.CKM_AES_GCM, p);
        using var second = new Mechanism(CKM.CKM_AES_GCM, p);

        using var scopeA = new MechanismParameterScope();
        using var scopeB = new MechanismParameterScope();

        var a = (CK_GCM_PARAMS)p.BuildMarshalable(scopeA);
        var b = (CK_GCM_PARAMS)p.BuildMarshalable(scopeB);

        Assert.NotEqual(a.Iv, b.Iv);   // independent buffers
        Assert.Equal((ulong)a.IvLen, (ulong)b.IvLen);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, first.Type);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, second.Type);
    }

    /// <summary>
    /// Asserts a pointer field addresses a live block holding exactly the expected bytes. A correct
    /// length beside an unwritten or wrongly sized buffer is the failure this catches.
    /// </summary>
    private static void AssertBlockHolds(IntPtr block, byte[] expected)
    {
        Assert.NotEqual(IntPtr.Zero, block);

        byte[] read = new byte[expected.Length];
        UnmanagedMemory.Read(block, read);
        Assert.Equal(expected, read);
    }

    private static ulong ReadHandle(IntPtr slot)
    {
        byte[] b = UnmanagedMemory.Read(slot, UnmanagedMemory.NativeULongSize);
        return UnmanagedMemory.NativeULongSize == 4
            ? BinaryPrimitives.ReadUInt32LittleEndian(b)
            : BinaryPrimitives.ReadUInt64LittleEndian(b);
    }
}
