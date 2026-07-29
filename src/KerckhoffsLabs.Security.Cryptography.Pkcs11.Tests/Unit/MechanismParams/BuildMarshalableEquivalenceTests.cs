using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// While both marshalling paths exist, the scope-based one must produce a struct identical to the
/// constructor-allocated one in every field except the pointers, which necessarily differ because
/// they address different blocks. Pointer-valued fields are compared as "both set" or "both zero".
/// </summary>
public sealed class BuildMarshalableEquivalenceTests
{
    [Fact]
    public void EddsaParams_BothPathsAgree()
    {
        using var p = new CkmEddsaParams(phFlag: true, [0xAA, 0xBB, 0xCC]);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_EDDSA_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_EDDSA_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(legacy.PhFlag, scoped.PhFlag);
        Assert.Equal((ulong)legacy.ContextDataLen, (ulong)scoped.ContextDataLen);
        Assert.NotEqual(IntPtr.Zero, scoped.ContextData);
        Assert.NotEqual(legacy.ContextData, scoped.ContextData); // distinct blocks

        Span<byte> read = stackalloc byte[3];
        UnmanagedMemory.Read(scoped.ContextData, read);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, read.ToArray());
    }

    [Fact]
    public void Rc2Params_AllocationFreeType_ReturnsTheSameStruct()
    {
        using var p = new CkmRc2Params(128);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_RC2_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_RC2_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.EffectiveBits, (ulong)scoped.EffectiveBits);
    }

    [Fact]
    public void EmptyBuffer_MarshalsAsNullPointer()
    {
        using var p = new CkmEddsaParams(phFlag: false, default);
        using var scope = new MechanismParameterScope();

        var scoped = (CK_EDDSA_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(IntPtr.Zero, scoped.ContextData);
        Assert.Equal(0UL, (ulong)scoped.ContextDataLen);
    }

    // ---------------------------------------------------------------------------------------------
    // The allocation-free types: their structs carry no pointer, so scalar equality is the whole test.
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void Rc2CbcParams_BothPathsAgree()
    {
        byte[] iv = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        using var p = new CkmRc2CbcParams(128, iv);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_RC2_CBC_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_RC2_CBC_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.EffectiveBits, (ulong)scoped.EffectiveBits);
        // Iv is an inline CkChar8 buffer, not a pointer, so the bytes travel inside the struct.
        Assert.True(((ReadOnlySpan<byte>)legacy.Iv).SequenceEqual(scoped.Iv));
        Assert.True(iv.AsSpan().SequenceEqual(scoped.Iv));
    }

    [Fact]
    public void RsaPkcsPssParams_BothPathsAgree()
    {
        using var p = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_RSA_PKCS_PSS_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_RSA_PKCS_PSS_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.HashAlg, (ulong)scoped.HashAlg);
        Assert.Equal((ulong)legacy.Mgf, (ulong)scoped.Mgf);
        Assert.Equal((ulong)legacy.Len, (ulong)scoped.Len);
    }

    [Fact]
    public void XeddsaParams_BothPathsAgree()
    {
        using var p = new CkmXeddsaParams(hashType: 1);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_XEDDSA_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_XEDDSA_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.Hash, (ulong)scoped.Hash);
    }

    // ---------------------------------------------------------------------------------------------
    // The single-buffer types: every scalar must match, and the pointer must address a distinct block
    // holding the same bytes.
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void HashPqcSignParams_BothPathsAgree()
    {
        using var p = new CkmHashPqcSignParams(CKM.CKM_SHA256, CkhHedge.CKH_HEDGE_REQUIRED, [0x01, 0x02]);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_HASH_SIGN_ADDITIONAL_CONTEXT)p.ToMarshalableStructure();
        var scoped = (CK_HASH_SIGN_ADDITIONAL_CONTEXT)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.HedgeVariant, (ulong)scoped.HedgeVariant);
        Assert.Equal((ulong)legacy.Hash, (ulong)scoped.Hash);
        Assert.Equal((ulong)legacy.ContextLen, (ulong)scoped.ContextLen);
        AssertDistinctBlockWithSameBytes(legacy.Context, scoped.Context, [0x01, 0x02]);
    }

    [Fact]
    public void Ike1ExtendedDeriveParams_BothPathsAgree()
    {
        using var p = new CkmIke1ExtendedDeriveParams(
            CKM.CKM_SHA256_HMAC, hasKeygxy: true, keygxy: 5, [0xE1, 0xE2]);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_IKE1_EXTENDED_DERIVE_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_IKE1_EXTENDED_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.PrfMechanism, (ulong)scoped.PrfMechanism);
        Assert.Equal(legacy.HasKeygxy, scoped.HasKeygxy);
        Assert.Equal((ulong)legacy.Keygxy, (ulong)scoped.Keygxy);
        Assert.Equal((ulong)legacy.ExtraDataLen, (ulong)scoped.ExtraDataLen);
        AssertDistinctBlockWithSameBytes(legacy.ExtraData, scoped.ExtraData, [0xE1, 0xE2]);
    }

    [Fact]
    public void Ike2PrfPlusDeriveParams_BothPathsAgree()
    {
        using var p = new CkmIke2PrfPlusDeriveParams(
            CKM.CKM_SHA256_HMAC, hasSeedKey: true, seedKey: 7, [0x5E, 0x5D, 0x5C]);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_IKE2_PRF_PLUS_DERIVE_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_IKE2_PRF_PLUS_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.PrfMechanism, (ulong)scoped.PrfMechanism);
        Assert.Equal(legacy.HasSeedKey, scoped.HasSeedKey);
        Assert.Equal((ulong)legacy.SeedKey, (ulong)scoped.SeedKey);
        Assert.Equal((ulong)legacy.SeedDataLen, (ulong)scoped.SeedDataLen);
        AssertDistinctBlockWithSameBytes(legacy.SeedData, scoped.SeedData, [0x5E, 0x5D, 0x5C]);
    }

    [Fact]
    public void PqcSignParams_BothPathsAgree()
    {
        using var p = new CkmPqcSignParams(CkhHedge.CKH_HEDGE_REQUIRED, [0xC0, 0xC1, 0xC2]);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_SIGN_ADDITIONAL_CONTEXT)p.ToMarshalableStructure();
        var scoped = (CK_SIGN_ADDITIONAL_CONTEXT)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.HedgeVariant, (ulong)scoped.HedgeVariant);
        Assert.Equal((ulong)legacy.ContextLen, (ulong)scoped.ContextLen);
        AssertDistinctBlockWithSameBytes(legacy.Context, scoped.Context, [0xC0, 0xC1, 0xC2]);
    }

    [Fact]
    public void RsaPkcsOaepParams_BothPathsAgree()
    {
        using var p = new CkmRsaPkcsOaepParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, [0x0A, 0x0B]);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_RSA_PKCS_OAEP_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_RSA_PKCS_OAEP_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.HashAlg, (ulong)scoped.HashAlg);
        Assert.Equal((ulong)legacy.Mgf, (ulong)scoped.Mgf);
        // Source is CKZ_DATA_SPECIFIED, hardcoded in both paths — a divergence here would mean one
        // path stopped declaring that the source data is present.
        Assert.Equal((ulong)legacy.Source, (ulong)scoped.Source);
        Assert.Equal((ulong)legacy.SourceDataLen, (ulong)scoped.SourceDataLen);
        AssertDistinctBlockWithSameBytes(legacy.SourceData, scoped.SourceData, [0x0A, 0x0B]);
    }

    [Fact]
    public void X2RatchetInitializeParams_BothPathsAgree()
    {
        byte[] sk = [0x51, 0x52, 0x53, 0x54];
        using var p = new CkmX2RatchetInitializeParams(
            sk, peerPublicPrekey: 1, peerPublicIdentity: 2, ownPublicIdentity: 3,
            encryptedHeader: true, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 5);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_X2RATCHET_INITIALIZE_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_X2RATCHET_INITIALIZE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.PeerPublicPrekey, (ulong)scoped.PeerPublicPrekey);
        Assert.Equal((ulong)legacy.PeerPublicIdentity, (ulong)scoped.PeerPublicIdentity);
        Assert.Equal((ulong)legacy.OwnPublicIdentity, (ulong)scoped.OwnPublicIdentity);
        Assert.Equal(legacy.EncryptedHeader, scoped.EncryptedHeader);
        Assert.Equal((ulong)legacy.Curve, (ulong)scoped.Curve);
        Assert.Equal((ulong)legacy.AeadMechanism, (ulong)scoped.AeadMechanism);
        Assert.Equal((ulong)legacy.KdfMechanism, (ulong)scoped.KdfMechanism);
        AssertDistinctBlockWithSameBytes(legacy.Sk, scoped.Sk, sk);
    }

    [Fact]
    public void X2RatchetRespondParams_BothPathsAgree()
    {
        byte[] sk = [0x61, 0x62, 0x63, 0x64];
        using var p = new CkmX2RatchetRespondParams(
            sk, ownPrekey: 1, initiatorIdentity: 2, ownPublicIdentity: 3,
            encryptedHeader: false, curve: 4, CKM.CKM_AES_GCM, kdfMechanism: 6);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_X2RATCHET_RESPOND_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_X2RATCHET_RESPOND_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.OwnPrekey, (ulong)scoped.OwnPrekey);
        Assert.Equal((ulong)legacy.InitiatorIdentity, (ulong)scoped.InitiatorIdentity);
        Assert.Equal((ulong)legacy.OwnPublicIdentity, (ulong)scoped.OwnPublicIdentity);
        Assert.Equal(legacy.EncryptedHeader, scoped.EncryptedHeader);
        Assert.Equal((ulong)legacy.Curve, (ulong)scoped.Curve);
        Assert.Equal((ulong)legacy.AeadMechanism, (ulong)scoped.AeadMechanism);
        Assert.Equal((ulong)legacy.KdfMechanism, (ulong)scoped.KdfMechanism);
        AssertDistinctBlockWithSameBytes(legacy.Sk, scoped.Sk, sk);
    }

    // ---------------------------------------------------------------------------------------------
    // The multi-buffer types: every scalar must match, and each pointer must address a distinct block
    // holding the same bytes.
    // ---------------------------------------------------------------------------------------------

    [Fact]
    public void AesGcmParams_BothPathsAgree()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] aad = [0xA0, 0xA1];
        using var p = new CkmAesGcmParams(iv, aad, tagBits: 128);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_GCM_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_GCM_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.IvLen, (ulong)scoped.IvLen);
        Assert.Equal((ulong)legacy.AADLen, (ulong)scoped.AADLen);
        Assert.Equal((ulong)legacy.TagBits, (ulong)scoped.TagBits);
        Assert.Equal((ulong)legacy.IvBits, (ulong)scoped.IvBits);

        Span<byte> readIv = stackalloc byte[12];
        UnmanagedMemory.Read(scoped.Iv, readIv);
        Assert.Equal(iv, readIv.ToArray());

        Span<byte> readAad = stackalloc byte[2];
        UnmanagedMemory.Read(scoped.AAD, readAad);
        Assert.Equal(aad, readAad.ToArray());
    }

    [Fact]
    public void AesGcmParams_EmptyAad_MarshalsAsNullPointer()
    {
        using var p = new CkmAesGcmParams(new byte[12], default, tagBits: 128);
        using var scope = new MechanismParameterScope();

        var scoped = (CK_GCM_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(IntPtr.Zero, scoped.AAD);
        Assert.Equal(0UL, (ulong)scoped.AADLen);
    }

    [Fact]
    public void AesCcmParams_BothPathsAgree()
    {
        byte[] nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        byte[] aad = [0xAA, 0xBB, 0xCC];
        using var p = new CkmAesCcmParams(dataLen: 64, nonce, aad, macLen: 16);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_CCM_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_CCM_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.DataLen, (ulong)scoped.DataLen);
        Assert.Equal((ulong)legacy.NonceLen, (ulong)scoped.NonceLen);
        Assert.Equal((ulong)legacy.AADLen, (ulong)scoped.AADLen);
        Assert.Equal((ulong)legacy.MACLen, (ulong)scoped.MACLen);
        AssertDistinctBlockWithSameBytes(legacy.Nonce, scoped.Nonce, nonce);
        AssertDistinctBlockWithSameBytes(legacy.AAD, scoped.AAD, aad);
    }

    [Fact]
    public void ChaCha20Params_BothPathsAgree()
    {
        byte[] blockCounter = [0x01, 0x00, 0x00, 0x00];
        byte[] nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
        using var p = new CkmChaCha20Params(blockCounter, blockCounterBits: 32, nonce, nonceBits: 96);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_CHACHA20_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_CHACHA20_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.BlockCounterBits, (ulong)scoped.BlockCounterBits);
        Assert.Equal((ulong)legacy.NonceBits, (ulong)scoped.NonceBits);
        AssertDistinctBlockWithSameBytes(legacy.BlockCounter, scoped.BlockCounter, blockCounter);
        AssertDistinctBlockWithSameBytes(legacy.Nonce, scoped.Nonce, nonce);
    }

    [Fact]
    public void Ecdh1DeriveParams_BothPathsAgree()
    {
        byte[] peerPublicPoint = [0x04, 0x01, 0x02, 0x03, 0x04, 0x05];
        byte[] sharedData = [0x77, 0x78, 0x79];
        using var p = new CkmEcdh1DeriveParams(CKD.CKD_SHA256_KDF, peerPublicPoint, sharedData);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_ECDH1_DERIVE_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_ECDH1_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.Kdf, (ulong)scoped.Kdf);
        Assert.Equal((ulong)legacy.SharedDataLen, (ulong)scoped.SharedDataLen);
        Assert.Equal((ulong)legacy.PublicDataLen, (ulong)scoped.PublicDataLen);
        AssertDistinctBlockWithSameBytes(legacy.PublicData, scoped.PublicData, peerPublicPoint);
        AssertDistinctBlockWithSameBytes(legacy.SharedData, scoped.SharedData, sharedData);
    }

    [Fact]
    public void HkdfParams_BothPathsAgree()
    {
        byte[] salt = [0x01, 0x02, 0x03];
        byte[] info = [0xF0, 0xF1, 0xF2, 0xF3];
        using var p = new CkmHkdfParams(
            extract: true, expand: true, CKM.CKM_SHA256_HMAC, saltType: 2, salt, saltKey: 9, info);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_HKDF_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_HKDF_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal(legacy.Extract, scoped.Extract);
        Assert.Equal(legacy.Expand, scoped.Expand);
        Assert.Equal((ulong)legacy.PrfHashMechanism, (ulong)scoped.PrfHashMechanism);
        Assert.Equal((ulong)legacy.SaltType, (ulong)scoped.SaltType);
        Assert.Equal((ulong)legacy.SaltLen, (ulong)scoped.SaltLen);
        Assert.Equal((ulong)legacy.SaltKey, (ulong)scoped.SaltKey);
        Assert.Equal((ulong)legacy.InfoLen, (ulong)scoped.InfoLen);
        AssertDistinctBlockWithSameBytes(legacy.Salt, scoped.Salt, salt);
        AssertDistinctBlockWithSameBytes(legacy.Info, scoped.Info, info);
    }

    [Fact]
    public void Ike1PrfDeriveParams_BothPathsAgree()
    {
        byte[] ckyI = [0x01, 0x02, 0x03, 0x04];
        byte[] ckyR = [0x05, 0x06, 0x07, 0x08];
        using var p = new CkmIke1PrfDeriveParams(
            CKM.CKM_SHA256_HMAC, hasPrevKey: true, keygxy: 11, prevKey: 22, ckyI, ckyR, keyNumber: 3);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_IKE1_PRF_DERIVE_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_IKE1_PRF_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.PrfMechanism, (ulong)scoped.PrfMechanism);
        Assert.Equal(legacy.HasPrevKey, scoped.HasPrevKey);
        Assert.Equal((ulong)legacy.Keygxy, (ulong)scoped.Keygxy);
        Assert.Equal((ulong)legacy.PrevKey, (ulong)scoped.PrevKey);
        Assert.Equal((ulong)legacy.CkyILen, (ulong)scoped.CkyILen);
        Assert.Equal((ulong)legacy.CkyRLen, (ulong)scoped.CkyRLen);
        Assert.Equal(legacy.KeyNumber, scoped.KeyNumber);
        AssertDistinctBlockWithSameBytes(legacy.CkyI, scoped.CkyI, ckyI);
        AssertDistinctBlockWithSameBytes(legacy.CkyR, scoped.CkyR, ckyR);
    }

    [Fact]
    public void IkePrfDeriveParams_BothPathsAgree()
    {
        byte[] ni = [0x21, 0x22, 0x23];
        byte[] nr = [0x31, 0x32, 0x33, 0x34];
        using var p = new CkmIkePrfDeriveParams(
            CKM.CKM_SHA256_HMAC, dataAsKey: true, rekey: true, ni, nr, newKey: 42);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_IKE_PRF_DERIVE_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_IKE_PRF_DERIVE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.PrfMechanism, (ulong)scoped.PrfMechanism);
        Assert.Equal(legacy.DataAsKey, scoped.DataAsKey);
        Assert.Equal(legacy.Rekey, scoped.Rekey);
        Assert.Equal((ulong)legacy.NiLen, (ulong)scoped.NiLen);
        Assert.Equal((ulong)legacy.NrLen, (ulong)scoped.NrLen);
        Assert.Equal((ulong)legacy.NewKey, (ulong)scoped.NewKey);
        AssertDistinctBlockWithSameBytes(legacy.Ni, scoped.Ni, ni);
        AssertDistinctBlockWithSameBytes(legacy.Nr, scoped.Nr, nr);
    }

    [Fact]
    public void Salsa20Params_BothPathsAgree()
    {
        byte[] blockCounter = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        byte[] nonce = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
        using var p = new CkmSalsa20Params(blockCounter, nonce, nonceBits: 64);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_SALSA20_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_SALSA20_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.NonceBits, (ulong)scoped.NonceBits);
        AssertDistinctBlockWithSameBytes(legacy.BlockCounter, scoped.BlockCounter, blockCounter);
        AssertDistinctBlockWithSameBytes(legacy.Nonce, scoped.Nonce, nonce);
    }

    [Fact]
    public void Salsa20ChaCha20Poly1305Params_BothPathsAgree()
    {
        byte[] nonce = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C];
        byte[] aad = [0x91, 0x92];
        using var p = new CkmSalsa20ChaCha20Poly1305Params(nonce, aad);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_SALSA20_CHACHA20_POLY1305_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_SALSA20_CHACHA20_POLY1305_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.NonceLen, (ulong)scoped.NonceLen);
        Assert.Equal((ulong)legacy.AADLen, (ulong)scoped.AADLen);
        AssertDistinctBlockWithSameBytes(legacy.Nonce, scoped.Nonce, nonce);
        AssertDistinctBlockWithSameBytes(legacy.AAD, scoped.AAD, aad);
    }

    [Fact]
    public void X3dhInitiateParams_BothPathsAgree()
    {
        byte[] prekeySignature = [0x51, 0x52, 0x53, 0x54, 0x55];
        byte[] onetimeKey = [0x61, 0x62, 0x63];
        using var p = new CkmX3dhInitiateParams(
            kdf: 1, peerIdentity: 2, peerPrekey: 3, prekeySignature, onetimeKey, ownIdentity: 4, ownEphemeral: 5);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_X3DH_INITIATE_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_X3DH_INITIATE_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.Kdf, (ulong)scoped.Kdf);
        Assert.Equal((ulong)legacy.PeerIdentity, (ulong)scoped.PeerIdentity);
        Assert.Equal((ulong)legacy.PeerPrekey, (ulong)scoped.PeerPrekey);
        Assert.Equal((ulong)legacy.OwnIdentity, (ulong)scoped.OwnIdentity);
        Assert.Equal((ulong)legacy.OwnEphemeral, (ulong)scoped.OwnEphemeral);
        AssertDistinctBlockWithSameBytes(legacy.PrekeySignature, scoped.PrekeySignature, prekeySignature);
        AssertDistinctBlockWithSameBytes(legacy.OnetimeKey, scoped.OnetimeKey, onetimeKey);
    }

    [Fact]
    public void X3dhRespondParams_BothPathsAgree()
    {
        byte[] identityId = [0x71, 0x72];
        byte[] prekeyId = [0x81, 0x82, 0x83];
        byte[] onetimeId = [0x91, 0x92, 0x93, 0x94];
        byte[] initiatorEphemeral = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
        using var p = new CkmX3dhRespondParams(
            kdf: 6, identityId, prekeyId, onetimeId, initiatorIdentity: 7, initiatorEphemeral);
        using var scope = new MechanismParameterScope();

        var legacy = (CK_X3DH_RESPOND_PARAMS)p.ToMarshalableStructure();
        var scoped = (CK_X3DH_RESPOND_PARAMS)p.BuildMarshalable(scope);

        Assert.Equal((ulong)legacy.Kdf, (ulong)scoped.Kdf);
        Assert.Equal((ulong)legacy.InitiatorIdentity, (ulong)scoped.InitiatorIdentity);
        AssertDistinctBlockWithSameBytes(legacy.IdentityId, scoped.IdentityId, identityId);
        AssertDistinctBlockWithSameBytes(legacy.PrekeyId, scoped.PrekeyId, prekeyId);
        AssertDistinctBlockWithSameBytes(legacy.OnetimeId, scoped.OnetimeId, onetimeId);
        AssertDistinctBlockWithSameBytes(legacy.InitiatorEphemeral, scoped.InitiatorEphemeral, initiatorEphemeral);
    }

    /// <summary>
    /// The scoped path must allocate its own block rather than reuse the constructor's, and that block
    /// must hold the same bytes. Reusing the legacy pointer would look correct in every length
    /// assertion while still leaving the parameter object owning memory the scope is meant to own.
    /// </summary>
    private static void AssertDistinctBlockWithSameBytes(IntPtr legacy, IntPtr scoped, byte[] expected)
    {
        Assert.NotEqual(IntPtr.Zero, scoped);
        Assert.NotEqual(legacy, scoped);

        byte[] read = new byte[expected.Length];
        UnmanagedMemory.Read(scoped, read);
        Assert.Equal(expected, read);
    }
}
