using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>Marshalling round trips for the KDF params (HKDF, SP800-108 KDF / feedback).</summary>
public sealed class MechanismKdfParamsTests
{
    [Fact]
    public void Hkdf_MarshalsSaltInfoAndFlags()
    {
        byte[] salt = [1, 2, 3, 4];
        byte[] info = [9, 8, 7];
        var p = CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256_HMAC, salt, info);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_HKDF_PARAMS>(p.BuildMarshalable(scope));

        Assert.True(s.Extract);
        Assert.True(s.Expand);
        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfHashMechanism);
        Assert.Equal((ulong)HkdfSaltType.Data, (ulong)s.SaltType);
        Assert.Equal((ulong)salt.Length, (ulong)s.SaltLen);
        Assert.Equal(salt, UnmanagedMemory.Read(s.Salt, salt.Length));
        Assert.Equal((ulong)info.Length, (ulong)s.InfoLen);
        Assert.Equal(info, UnmanagedMemory.Read(s.Info, info.Length));
    }

    [Fact]
    public void Hkdf_EmptySaltAndInfo_NullPointers()
    {
        var p = CkmHkdfParams.WithoutSalt(HkdfOperation.ExpandOnly, CKM.CKM_SHA256_HMAC);
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_HKDF_PARAMS>(p.BuildMarshalable(scope));

        Assert.False(s.Extract);
        Assert.True(s.Expand);
        Assert.Equal(IntPtr.Zero, s.Salt);
        Assert.Equal(0UL, (ulong)s.SaltLen);
        Assert.Equal(IntPtr.Zero, s.Info);
        Assert.Equal(0UL, (ulong)s.InfoLen);
    }

    [Fact]
    public void Sp800108Kdf_MarshalsPrfAndDataParamCount()
    {
        var p = CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray([1, 2, 3]).ByteArray([0x00]).ByteArray([4, 5])
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys).Build();
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_SP800_108_KDF_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfType);
        Assert.Equal(5UL, (ulong)s.NumberOfDataParams);
    }

    [Fact]
    public void Sp800108FeedbackKdf_MarshalsIvAndPrf()
    {
        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8];
        var p = CkmSp800108KdfParams.Feedback(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray([9]).DkmLength(Sp800108DkmLengthMethod.SumOfKeys)
            .WithIV(iv).Build();
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_SP800_108_FEEDBACK_KDF_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal((ulong)CKM.CKM_SHA256_HMAC, (ulong)s.PrfType);
        Assert.Equal(3UL, (ulong)s.NumberOfDataParams);
        Assert.Equal((ulong)iv.Length, (ulong)s.IVLen);
        Assert.Equal(iv, UnmanagedMemory.Read(s.IV, iv.Length));
    }

    [Fact]
    public void Sp800108FeedbackKdf_EmptyIv_NullPointer()
    {
        var p = CkmSp800108KdfParams.Feedback(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray([9]).DkmLength(Sp800108DkmLengthMethod.SumOfKeys).Build();
        using var scope = new MechanismParameterScope();
        var s = ParamMarshal.RoundTrip<CK_SP800_108_FEEDBACK_KDF_PARAMS>(p.BuildMarshalable(scope));

        Assert.Equal(0UL, (ulong)s.IVLen);
        Assert.Equal(IntPtr.Zero, s.IV);
    }
}
