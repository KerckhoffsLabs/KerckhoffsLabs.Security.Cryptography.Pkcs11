using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// Which <c>CKM_PKCS5_PBKD2</c> parameter layout a module receives. <c>CK_PKCS5_PBKD2_PARAMS</c> (v2.40)
/// and <c>CK_PKCS5_PBKD2_PARAMS2</c> (v3.0) have the same size and differ only in <c>ulPasswordLen</c>:
/// a pointer in the first, a value in the second. A v2.40 module given the second dereferences the
/// password length as an address — NSS softoken 3.51 segfaults — so a module bound only through its
/// v2.40 function list must get the first.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs5Pbkd2ParamsLayoutTests
{
    private static readonly byte[] Salt = "pbkdf2-salt-0123"u8.ToArray();

    [Fact]
    public void V240OnlyModule_ReceivesThePasswordLengthThroughAPointer()
    {
        using var module = new V240Module();
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);
        Assert.False(session.IsBoundThroughV3Interface);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal("correct horse"u8.ToArray(), module.Password);
        Assert.Equal(Salt, module.Salt);
        Assert.Equal(1000UL, module.Iterations);
    }

    [Fact]
    public void V3Module_ReceivesThePasswordLengthByValue()
    {
        using var module = new V3Module();
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);
        Assert.True(session.IsBoundThroughV3Interface);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal("correct horse"u8.ToArray(), module.Password);
        Assert.Equal(Salt, module.Salt);
        Assert.Equal(1000UL, module.Iterations);
    }

    /// <summary>An empty password still gets a length to point at, not a null pointer.</summary>
    [Fact]
    public void V240OnlyModule_EmptyPassword_PointsAtAZeroLength()
    {
        using var module = new V240Module();
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, ReadOnlySpan<byte>.Empty);

        Assert.Empty(Assert.IsType<byte[]>(module.Password));
    }

    private static void GenerateKey(Pkcs11Session session, ReadOnlySpan<byte> password)
    {
        var parameters = new CkmPkcs5Pbkd2Params(Salt, 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, password);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();
        session.GenerateKey(new Mechanism(CKM.CKM_PKCS5_PBKD2, parameters), [.. template.Attributes]);
    }

    private abstract class Pbkd2Module : SessionTestModule
    {
        public byte[]? Password { get; protected set; }
        public byte[]? Salt { get; protected set; }
        public ulong Iterations { get; protected set; }

        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            if ((CKM)(ulong)mechanism.Mechanism != CKM.CKM_PKCS5_PBKD2)
                return CKR.CKR_MECHANISM_INVALID;
            Read(mechanism.Parameter);
            key = (NativeCULong)42UL;
            return CKR.CKR_OK;
        }

        protected abstract void Read(IntPtr parameter);

        protected static byte[] Bytes(IntPtr data, ulong length)
            => length == 0 ? [] : UnmanagedMemory.Read(data, checked((int)length));
    }

    // Overrides v2.40 functions only, so it exports just C_GetFunctionList, like NSS 3.51.
    private sealed class V240Module : Pbkd2Module
    {
        protected override void Read(IntPtr parameter)
        {
            var p = UnmanagedMemory.Read<CK_PKCS5_PBKD2_PARAMS>(parameter);
            // A length sent by value lands here as a tiny "address". Dereferencing it, as NSS 3.51 does,
            // would take the test host down; fail the call instead (the thunk records the exception).
            if ((ulong)p.PasswordLen < 0x10000)
                throw new InvalidOperationException($"ulPasswordLen holds 0x{(ulong)p.PasswordLen:x}, a length rather than a pointer to one.");
            ulong passwordLen = (ulong)UnmanagedMemory.Read<NativeCULong>(p.PasswordLen);
            Password = Bytes(p.Password, passwordLen);
            Salt = Bytes(p.SaltSourceData, (ulong)p.SaltSourceDataLen);
            Iterations = (ulong)p.Iterations;
        }
    }

    // Implementing a v3.0 function makes the fake hand out a v3.x interface table.
    private sealed class V3Module : Pbkd2Module
    {
        protected override CKR C_GetInterfaceList(bool listIsNull, Span<CK_INTERFACE> interfaces, ref NativeCULong count)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;

        protected override void Read(IntPtr parameter)
        {
            var p = UnmanagedMemory.Read<CK_PKCS5_PBKD2_PARAMS2>(parameter);
            Password = Bytes(p.Password, (ulong)p.PasswordLen);
            Salt = Bytes(p.SaltSourceData, (ulong)p.SaltSourceDataLen);
            Iterations = (ulong)p.Iterations;
        }
    }
}
