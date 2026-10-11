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
/// and <c>CK_PKCS5_PBKD2_PARAMS2</c> (v2.40 Errata 01, v3.0) differ only in <c>ulPasswordLen</c>: a
/// pointer in the first, a value in the second. NSS softoken before 3.114 reads the first whatever
/// version it implements, and given the second dereferences the length as an address and segfaults;
/// every other module gets the second unless the options say otherwise.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs5Pbkd2ParamsLayoutTests
{
    private const string Mozilla = "Mozilla Foundation";
    private static readonly byte[] Salt = "pbkdf2-salt-0123"u8.ToArray();

    [Theory]
    [InlineData(Mozilla, 3, 51, true)]    // implements v2.40 only
    [InlineData(Mozilla, 3, 98, true)]    // implements v3.0, still reads the pointer
    [InlineData(Mozilla, 3, 113, true)]   // the last release that does
    [InlineData(Mozilla, 3, 114, false)]  // accepts either, and may be built to accept only the value
    [InlineData(Mozilla, 3, 130, false)]
    [InlineData("SoftHSM", 2, 51, false)] // only the manufacturer marks NSS, not the version alone
    public void Detect_SendsThePointerOnlyToNssBefore3_114(string manufacturer, byte major, byte minor, bool byReference)
    {
        using var module = new Pbkd2Module(manufacturer, major, minor);
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal(byReference, module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
        Assert.Equal(Salt, module.Salt);
        Assert.Equal(1000UL, module.Iterations);
    }

    /// <summary>
    /// NSS 3.52 to 3.113 hand out a v3.0 interface and still read the pointer, so the function list a
    /// module was bound through cannot decide the layout.
    /// </summary>
    [Fact]
    public void Detect_NssBoundThroughAV3Interface_StillGetsThePointer()
    {
        using var module = new V3Pbkd2Module(Mozilla, 3, 98);
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, "correct horse"u8);

        Assert.True(module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
    }

    [Fact]
    public void Detect_ModuleWithoutGetInfo_GetsTheStandardStructure()
    {
        using var module = new Pbkd2Module(manufacturer: null);
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, "correct horse"u8);

        Assert.False(module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
    }

    [Fact]
    public void Detect_AsksGetInfoOnce()
    {
        using var module = new Pbkd2Module(Mozilla, 3, 51);
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, "correct horse"u8);
        GenerateKey(session, "correct horse"u8);

        Assert.Equal(1, module.GetInfoCalls);
        Assert.True(module.LowLevel.Pbkdf2PasswordLengthByReference);
    }

    [Theory]
    [InlineData("SoftHSM", true)]
    [InlineData(Mozilla, false)]
    public void ConfiguredLayout_OverridesDetection_WithoutAskingGetInfo(string manufacturer, bool byReference)
    {
        using var module = new Pbkd2Module(manufacturer, 3, 51);
        module.LowLevel.Pbkdf2PasswordLengthByReference = byReference;
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal(byReference, module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
        Assert.Equal(0, module.GetInfoCalls);
    }

    /// <summary>An empty password still gets a length to point at, not a null pointer.</summary>
    [Fact]
    public void ByReference_EmptyPassword_PointsAtAZeroLength()
    {
        using var module = new Pbkd2Module(Mozilla, 3, 51);
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, []);

        Assert.True(module.SentByReference);
        Assert.Empty(Assert.IsType<byte[]>(module.Password));
    }

    [Theory]
    [InlineData(Pbkdf2ParametersLayout.Detect, null)]
    [InlineData(Pbkdf2ParametersLayout.PasswordLengthByValue, false)]
    [InlineData(Pbkdf2ParametersLayout.PasswordLengthByReference, true)]
    public void Options_Layout_ReachesTheModuleBinding(Pbkdf2ParametersLayout layout, bool? byReference)
    {
        using var module = new Pbkd2Module(Mozilla, 3, 51);

        using var library = module.Load(new Pkcs11LibraryOptions { Pbkdf2ParametersLayout = layout });

        Assert.Equal(byReference, library.LowLevelLibrary!.Pbkdf2PasswordLengthByReference);
    }

    [Fact]
    public void Options_DefaultLayout_IsDetect()
        => Assert.Equal(Pbkdf2ParametersLayout.Detect, new Pkcs11LibraryOptions().Pbkdf2ParametersLayout);

    [Fact]
    public void Options_UndefinedLayout_IsRefused()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new Pkcs11LibraryOptions { Pbkdf2ParametersLayout = (Pbkdf2ParametersLayout)42 });
        Assert.Equal(nameof(Pkcs11LibraryOptions.Pbkdf2ParametersLayout), ex.ParamName);
    }

    private static void GenerateKey(Pkcs11Session session, ReadOnlySpan<byte> password)
    {
        var parameters = new CkmPkcs5Pbkd2Params(Salt, 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, password);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();
        session.GenerateKey(new Mechanism(CKM.CKM_PKCS5_PBKD2, parameters), [.. template.Attributes]);
    }

    // Reports manufacturer and library version from C_GetInfo, or refuses it when the manufacturer is
    // null, and records which layout each CKM_PKCS5_PBKD2 call carried. Overrides v2.40 functions only,
    // so it exports just C_GetFunctionList.
    private class Pbkd2Module(string? manufacturer, byte libraryMajor = 0, byte libraryMinor = 0) : SessionTestModule
    {
        public int GetInfoCalls { get; private set; }
        public bool? SentByReference { get; private set; }
        public byte[]? Password { get; private set; }
        public byte[]? Salt { get; private set; }
        public ulong Iterations { get; private set; }

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            GetInfoCalls++;
            if (manufacturer is null)
                return CKR.CKR_FUNCTION_NOT_SUPPORTED;
            info.CryptokiVersion = new CK_VERSION { Major = 3, Minor = 0 };
            NativeTestStructs.FillPadded(info.ManufacturerId, manufacturer);
            NativeTestStructs.FillPadded(info.LibraryDescription, "PBKDF2 layout test module");
            info.LibraryVersion = new CK_VERSION { Major = libraryMajor, Minor = libraryMinor };
            return CKR.CKR_OK;
        }

        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            if ((CKM)(ulong)mechanism.Mechanism != CKM.CKM_PKCS5_PBKD2)
                return CKR.CKR_MECHANISM_INVALID;

            // On 64-bit Unix the two layouts have the same size, so tell them apart as NSS 3.114 does:
            // a length is small, an address is not. Never dereference a length, which would take the
            // test host down the way NSS takes a process down.
            var p = UnmanagedMemory.Read<CK_PKCS5_PBKD2_PARAMS2>(mechanism.Parameter);
            SentByReference = (ulong)p.PasswordLen >= 0x10000;
            ulong passwordLen;
            if (SentByReference.Value)
            {
                Assert.Equal((ulong)Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS>(), (ulong)mechanism.ParameterLen);
                var original = UnmanagedMemory.Read<CK_PKCS5_PBKD2_PARAMS>(mechanism.Parameter);
                passwordLen = (ulong)UnmanagedMemory.Read<NativeCULong>(original.PasswordLen);
            }
            else
            {
                Assert.Equal((ulong)Pkcs11Marshal.SizeOf<CK_PKCS5_PBKD2_PARAMS2>(), (ulong)mechanism.ParameterLen);
                passwordLen = (ulong)p.PasswordLen;
            }

            Password = Bytes(p.Password, passwordLen);
            Salt = Bytes(p.SaltSourceData, (ulong)p.SaltSourceDataLen);
            Iterations = (ulong)p.Iterations;
            key = (NativeCULong)42UL;
            return CKR.CKR_OK;
        }

        private static byte[] Bytes(IntPtr data, ulong length)
            => length == 0 ? [] : UnmanagedMemory.Read(data, checked((int)length));
    }

    // Implementing a v3.0 function makes the fake hand out a v3.x interface table.
    private sealed class V3Pbkd2Module(string manufacturer, byte libraryMajor, byte libraryMinor)
        : Pbkd2Module(manufacturer, libraryMajor, libraryMinor)
    {
        protected override CKR C_GetInterfaceList(bool listIsNull, Span<CK_INTERFACE> interfaces, ref NativeCULong count)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    }
}
