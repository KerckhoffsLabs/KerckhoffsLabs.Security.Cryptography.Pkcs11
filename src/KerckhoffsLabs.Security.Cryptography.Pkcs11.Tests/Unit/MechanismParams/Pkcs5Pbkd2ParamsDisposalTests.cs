using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// <see cref="CkmPkcs5Pbkd2Params"/> holds the password, so it zeroes its copy on disposal and a
/// disposed instance cannot be marshalled.
/// </summary>
public sealed class Pkcs5Pbkd2ParamsDisposalTests
{
    [Fact]
    public void BeforeDisposal_MarshalsThePassword()
    {
        using var p = new CkmPkcs5Pbkd2Params(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, "pw"u8);
        using var scope = new MechanismParameterScope();

        var s = (CK_PKCS5_PBKD2_PARAMS2)p.BuildMarshalable(scope);

        Assert.Equal("pw"u8.ToArray(), UnmanagedMemory.Read(s.Password, (int)(ulong)s.PasswordLen));
    }

    [Fact]
    public void AfterDisposal_RefusesToMarshal()
    {
        var p = new CkmPkcs5Pbkd2Params(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, "pw"u8);
        p.Dispose();
        using var scope = new MechanismParameterScope();

        Assert.Throws<ObjectDisposedException>(() => p.BuildMarshalable(scope));
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var p = new CkmPkcs5Pbkd2Params(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, "pw"u8);
        p.Dispose();
        p.Dispose();
    }

    [Fact]
    public void EmptyPassword_IsAccepted()
    {
        using var p = new CkmPkcs5Pbkd2Params(new byte[16], 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, default);
        using var scope = new MechanismParameterScope();

        var s = (CK_PKCS5_PBKD2_PARAMS2)p.BuildMarshalable(scope);

        Assert.Equal(0UL, (ulong)s.PasswordLen);
    }
}
