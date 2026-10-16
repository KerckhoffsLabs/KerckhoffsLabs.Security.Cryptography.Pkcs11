using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>Marshalling round trips for the PQC sign / XEdDSA params.</summary>
public sealed class MechanismPqcSignParamsTests
{
    [Fact]
    public void PqcSign_MarshalsHedgeAndContext()
    {
        byte[] context = [0x01, 0x02, 0x03];
        var p = new CkmPqcSignParams(CkhHedge.CKH_HEDGE_REQUIRED, context);
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_SIGN_ADDITIONAL_CONTEXT>();

        Assert.Equal((ulong)CkhHedge.CKH_HEDGE_REQUIRED, (ulong)s.HedgeVariant);
        Assert.Equal((ulong)context.Length, (ulong)s.ContextLen);
        Assert.Equal(context, UnmanagedMemory.Read(s.Context, context.Length));
    }

    [Fact]
    public void PqcSign_DefaultHedge_EmptyContext_NullPointer()
    {
        var p = new CkmPqcSignParams();
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_SIGN_ADDITIONAL_CONTEXT>();

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
        var p = new CkmHashPqcSignParams(CKM.CKM_SHA256, CkhHedge.CKH_HEDGE_REQUIRED, context);
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_HASH_SIGN_ADDITIONAL_CONTEXT>();

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
        var p = new CkmXeddsaParams(CKM.CKM_SHA512);
        using var scope = new MechanismParameterScope();
        var s = p.BuildMarshalable(scope).Read<CK_XEDDSA_PARAMS>();

        Assert.Equal((ulong)CKM.CKM_SHA512, (ulong)s.Hash);
    }
}
