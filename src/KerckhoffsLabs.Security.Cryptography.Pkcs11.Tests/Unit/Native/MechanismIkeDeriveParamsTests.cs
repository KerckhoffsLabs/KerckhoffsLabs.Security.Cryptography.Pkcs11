using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>Marshalling round trips for the IKE derive params.</summary>
public sealed class MechanismIkeDeriveParamsTests
{
    [Fact]
    public void IkePrfDerive_MarshalsNoncesFlagsAndKey()
    {
        byte[] ni = [1, 2, 3];
        byte[] nr = [4, 5];
        using var keys = new ParameterKeys();
        var p = new CkmIkePrfDeriveParams(CKM.CKM_SHA256_HMAC, dataAsKey: true, rekey: false, ni, nr, newKey: keys.Secret(7));
        using var scope = keys.NewScope();
        var s = ParamMarshal.RoundTrip<CK_IKE_PRF_DERIVE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.Equal(CkBbool.True, s.DataAsKey);
        Assert.Equal(CkBbool.False, s.Rekey);
        Assert.Equal(ni, UnmanagedMemory.Read(s.Ni, ni.Length));
        Assert.Equal(nr, UnmanagedMemory.Read(s.Nr, nr.Length));
        Assert.Equal(7UL, (ulong)s.NewKey);
    }

    [Fact]
    public void Ike1PrfDerive_MarshalsCookiesFlagAndKeyNumber()
    {
        byte[] ckyI = [0x11, 0x22];
        byte[] ckyR = [0x33];
        using var keys = new ParameterKeys();
        var p = new CkmIke1PrfDeriveParams(CKM.CKM_SHA256_HMAC,
            keygxy: keys.Secret(1), prevKey: keys.Secret(2), ckyI, ckyR, keyNumber: 9);
        using var scope = keys.NewScope();
        var s = ParamMarshal.RoundTrip<CK_IKE1_PRF_DERIVE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfMechanism);
        Assert.Equal(CkBbool.True, s.HasPrevKey);
        Assert.Equal(ckyI, UnmanagedMemory.Read(s.CkyI, ckyI.Length));
        Assert.Equal(ckyR, UnmanagedMemory.Read(s.CkyR, ckyR.Length));
        Assert.Equal((byte)9, s.KeyNumber);
    }

    [Fact]
    public void Ike1ExtendedDerive_MarshalsFlagAndExtraData()
    {
        byte[] extra = [0xDE, 0xAD];
        using var keys = new ParameterKeys();
        var p = new CkmIke1ExtendedDeriveParams(CKM.CKM_SHA256_HMAC, keygxy: keys.Secret(5), extra);
        using var scope = keys.NewScope();
        var s = ParamMarshal.RoundTrip<CK_IKE1_EXTENDED_DERIVE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(CkBbool.True, s.HasKeygxy);
        Assert.Equal(5UL, (ulong)s.Keygxy);
        Assert.Equal((ulong)extra.Length, (ulong)s.ExtraDataLen);
        Assert.Equal(extra, UnmanagedMemory.Read(s.ExtraData, extra.Length));
    }

    [Fact]
    public void Ike2PrfPlusDerive_MarshalsFlagAndSeedData()
    {
        byte[] seed = [0xBE, 0xEF, 0x01];
        var p = new CkmIke2PrfPlusDeriveParams(CKM.CKM_SHA256_HMAC, seedKey: null, seed);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(CkBbool.False, s.HasSeedKey);
        Assert.Equal(0UL, (ulong)s.SeedKey);
        Assert.Equal((ulong)seed.Length, (ulong)s.SeedDataLen);
        Assert.Equal(seed, UnmanagedMemory.Read(s.SeedData, seed.Length));
    }
}
