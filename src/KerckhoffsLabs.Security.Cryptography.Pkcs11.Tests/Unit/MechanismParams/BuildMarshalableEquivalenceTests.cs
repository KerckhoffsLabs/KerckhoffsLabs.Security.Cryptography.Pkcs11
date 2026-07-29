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
}
