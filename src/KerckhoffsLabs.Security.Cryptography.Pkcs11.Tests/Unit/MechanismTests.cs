using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

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
}
