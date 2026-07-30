using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

// Covers the raw-ulong Mechanism constructors (the CKM-typed siblings are exercised throughout the
// crypto suite). No token needed — these only build the CK_MECHANISM value.
public sealed class MechanismTests
{
    [Fact]
    public void Ctor_RawUlong_NoParameter_SetsType()
    {
        using var mech = new Mechanism((ulong)CKM.CKM_AES_KEY_GEN);
        Assert.Equal((ulong)CKM.CKM_AES_KEY_GEN, mech.Type);
        Assert.Null(mech.Parameters);
    }

    [Fact]
    public void Ctor_RawUlong_ByteArrayParameter_SetsType()
    {
        using var mech = new Mechanism((ulong)CKM.CKM_AES_GCM, [0x01, 0x02, 0x03]);
        Assert.Equal((ulong)CKM.CKM_AES_GCM, mech.Type);
    }

    [Fact]
    public void Ctor_RawUlong_MechanismParameters_SetsTypeAndKeepsParameter()
    {
        var p = new CkmPqcSignParams();
        using var mech = new Mechanism((ulong)CKM.CKM_ML_DSA, p);
        Assert.Equal((ulong)CKM.CKM_ML_DSA, mech.Type);
        Assert.Same(p, mech.Parameters);
    }

    [Fact]
    public void Ctor_RawUlong_NullMechanismParameters_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new Mechanism((ulong)CKM.CKM_ML_DSA, (MechanismParameters)null!));

    // Marshal must stay a pure function of (mechanism, scope). One instance can be marshalled twice
    // for two live operations — two sessions, or the same instance passed as both arguments of
    // DecryptVerify — and each needs its own block, so that absorbing one cannot read the other's
    // output. Returning the struct rather than caching it on the mechanism is what makes that hold;
    // the signature itself prevents a regression to a cache, and this pins the independence the
    // caller's per-operation locals rely on.
    [Fact]
    public void Marshal_TwiceOnOneInstance_YieldsIndependentBlocks()
    {
        using var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);
        using var mech = new Mechanism(CKM.CKM_AES_GCM, p);
        using var scope = new MechanismParameterScope();

        CK_MECHANISM first = mech.Marshal(scope, out object? firstParams);
        CK_MECHANISM second = mech.Marshal(scope, out object? secondParams);

        Assert.NotNull(firstParams);
        Assert.NotNull(secondParams);
        Assert.NotEqual(first.Parameter, second.Parameter);
        Assert.NotEqual(
            ((CK_GCM_MESSAGE_PARAMS)firstParams).Tag,
            ((CK_GCM_MESSAGE_PARAMS)secondParams).Tag);
    }

    [Fact]
    public void AbsorbOutput_NullMarshalledParams_IsNoOp()
    {
        using var mech = new Mechanism(CKM.CKM_AES_KEY_GEN);
        using var scope = new MechanismParameterScope();

        mech.Marshal(scope, out object? mechParams);

        // Parameterless mechanisms marshal to a null struct; absorbing it must do nothing rather
        // than throw, because every converted session site absorbs unconditionally.
        Assert.Null(mechParams);
        Assert.Null(Record.Exception(() => mech.AbsorbOutput(mechParams)));
    }
}
