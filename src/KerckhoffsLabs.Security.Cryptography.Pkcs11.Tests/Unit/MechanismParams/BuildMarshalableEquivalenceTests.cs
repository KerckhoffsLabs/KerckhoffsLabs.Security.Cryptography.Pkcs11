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
