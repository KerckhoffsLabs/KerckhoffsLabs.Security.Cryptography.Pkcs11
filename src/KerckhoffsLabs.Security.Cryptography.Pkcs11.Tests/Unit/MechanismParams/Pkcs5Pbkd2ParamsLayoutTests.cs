using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.MechanismParams;

/// <summary>
/// Which <c>CKM_PKCS5_PBKD2</c> parameter layout a slot receives. <c>CK_PKCS5_PBKD2_PARAMS</c> (v2.40)
/// and <c>CK_PKCS5_PBKD2_PARAMS2</c> (v2.40 Errata 01, v3.0) differ only in <c>ulPasswordLen</c>: a
/// pointer in the first, a value in the second. NSS softoken before 3.114 reads the first whatever
/// version it implements, and given the second dereferences the length as an address and segfaults; a
/// module implementing a Cryptoki version before 2.40 can only read the first. Every other slot gets the
/// second unless the options say otherwise. The decision is made once per slot, from
/// <c>C_GetSlotInfo</c>, which identifies NSS directly and behind a proxy alike, and else from the
/// Cryptoki version in <c>C_GetInfo</c>. Every session here is opened through <see cref="Pkcs11Slot"/>,
/// which is what tells the session its slot.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs5Pbkd2ParamsLayoutTests
{
    private const string Mozilla = "Mozilla Foundation";
    private const string P11Kit = "PKCS#11 Kit";
    private const string SoftHsm = "SoftHSM project";
    private static readonly byte[] Salt = "pbkdf2-salt-0123"u8.ToArray();

    /// <summary>NSS reports its manufacturer and release in each slot, loaded directly or behind p11-kit.</summary>
    [Theory]
    [InlineData(Mozilla, 3, 51, true)]    // implements v2.40 only
    [InlineData(Mozilla, 3, 98, true)]    // implements v3.0, still reads the pointer
    [InlineData(Mozilla, 3, 113, true)]   // the last release that does
    [InlineData(Mozilla, 3, 114, false)]  // accepts either, and may be built to accept only the value
    [InlineData(Mozilla, 3, 130, false)]
    [InlineData(P11Kit, 3, 51, true)]
    [InlineData(P11Kit, 3, 98, true)]
    [InlineData(P11Kit, 3, 113, true)]
    [InlineData(P11Kit, 3, 114, false)]
    [InlineData(P11Kit, 3, 130, false)]
    public void Detect_NssSlot_GetsThePointerBefore3_114(string moduleManufacturer, byte major, byte minor, bool byReference)
    {
        using var module = new Pbkd2Module(moduleManufacturer);
        module.Slots[0x11] = (Mozilla, major, minor);
        using var session = module.OpenSession(slot: 0x11);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal(byReference, module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
        Assert.Equal(Salt, module.Salt);
        Assert.Equal(1000UL, module.Iterations);
        Assert.Equal(0, module.GetInfoCalls);
    }

    /// <summary>Only the manufacturer marks NSS, not a version that happens to look like one.</summary>
    [Theory]
    [InlineData(2, 6)]
    [InlineData(3, 51)]
    public void Detect_OtherSlot_GetsTheValue(byte major, byte minor)
    {
        using var module = new Pbkd2Module(P11Kit);
        module.Slots[1] = (SoftHsm, major, minor);
        using var session = module.OpenSession(slot: 1);

        GenerateKey(session, "correct horse"u8);

        Assert.False(module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
    }

    /// <summary>
    /// NSS 3.52 to 3.113 hand out a v3.0 interface and still read the pointer, so the function list a
    /// module was bound through cannot decide the layout.
    /// </summary>
    [Fact]
    public void Detect_NssBoundThroughAV3Interface_StillGetsThePointer()
    {
        using var module = new V3Pbkd2Module(Mozilla);
        module.Slots[1] = (Mozilla, 3, 98);
        using var session = module.OpenSession(slot: 1);

        GenerateKey(session, "correct horse"u8);

        Assert.True(module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
    }

    /// <summary>
    /// The corrected structure first appeared in v2.40 Errata 01, so a module implementing an earlier
    /// version gets the original one. From v2.40 on, the version says nothing.
    /// </summary>
    [Theory]
    [InlineData(2, 11, true)]
    [InlineData(2, 20, true)]
    [InlineData(2, 30, true)]
    [InlineData(2, 40, false)]
    [InlineData(3, 0, false)]
    [InlineData(3, 2, false)]
    public void Detect_ModuleBeforeV2_40_GetsThePointer(byte cryptokiMajor, byte cryptokiMinor, bool byReference)
    {
        using var module = new Pbkd2Module("Acme HSM", cryptokiMajor, cryptokiMinor);
        module.Slots[1] = ("Acme HSM", 5, 1);
        using var session = module.OpenSession(slot: 1);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal(byReference, module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
    }

    /// <summary>The slot is more specific than the module, so an NSS slot decides even behind an old proxy.</summary>
    [Theory]
    [InlineData(3, 98, true)]
    [InlineData(3, 130, false)]
    public void Detect_NssSlotBehindAPreV2_40Proxy_FollowsTheSlot(byte major, byte minor, bool byReference)
    {
        using var module = new Pbkd2Module(P11Kit, cryptokiMajor: 2, cryptokiMinor: 20);
        module.Slots[1] = (Mozilla, major, minor);
        using var session = module.OpenSession(slot: 1);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal(byReference, module.SentByReference);
    }

    /// <summary>A module that does not describe its slots is still judged by its version.</summary>
    [Theory]
    [InlineData(2, 20, true)]
    [InlineData(3, 0, false)]
    public void Detect_SlotInfoNotSupported_FallsBackOnTheModuleVersion(byte cryptokiMajor, byte cryptokiMinor, bool byReference)
    {
        using var module = new Pbkd2Module("Acme HSM", cryptokiMajor, cryptokiMinor);
        using var session = module.OpenSession(slot: 7); // C_GetSlotInfo: CKR_FUNCTION_NOT_SUPPORTED

        GenerateKey(session, "correct horse"u8);

        Assert.Equal(byReference, module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
    }

    [Fact]
    public void Detect_ModuleDescribingNothing_GetsTheStandardStructure()
    {
        using var module = new Pbkd2Module(moduleManufacturer: null);
        using var session = module.OpenSession(slot: 7);

        GenerateKey(session, "correct horse"u8);

        Assert.False(module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
    }

    /// <summary>
    /// A proxy can put modules that read different layouts behind one library, so the answer for one
    /// slot must not decide for another, whichever slot derives first.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Detect_ProxyMixingModules_DecidesPerSlot(bool nssFirst)
    {
        using var module = new Pbkd2Module(P11Kit);
        module.Slots[1] = (Mozilla, 3, 98);
        module.Slots[2] = (SoftHsm, 2, 6);
        using var nss = module.OpenSession(slot: 1);
        using var softHsm = module.OpenSession(slot: 2);

        bool[] order = nssFirst ? [true, false, true, false] : [false, true, false, true];
        foreach (bool onNss in order)
        {
            GenerateKey(onNss ? nss : softHsm, "correct horse"u8);
            Assert.Equal(onNss, module.SentByReference);
            Assert.Equal("correct horse"u8.ToArray(), module.Password);
        }

        Assert.Equal(2, module.GetSlotInfoCalls);
        Assert.Equal(1, module.GetInfoCalls); // for the SoftHSM slot only
    }

    [Fact]
    public void Detect_AsksOncePerSlot()
    {
        using var module = new Pbkd2Module(P11Kit);
        module.Slots[1] = (SoftHsm, 2, 6);
        using var first = module.OpenSession(slot: 1);
        using var second = module.OpenSession(slot: 1);

        GenerateKey(first, "correct horse"u8);
        GenerateKey(second, "correct horse"u8);
        GenerateKey(first, "correct horse"u8);

        Assert.False(module.SentByReference);
        Assert.Equal(1, module.GetSlotInfoCalls);
        Assert.Equal(1, module.GetInfoCalls);
        Assert.False(module.LowLevel.Pbkdf2PasswordLengthByReferenceBySlot[1]);
    }

    /// <summary>
    /// Any failure but <c>CKR_FUNCTION_NOT_SUPPORTED</c> fails the derivation rather than guessing, which
    /// on an NSS slot would crash the process, and decides nothing: the next derivation asks again.
    /// </summary>
    [Theory]
    [InlineData(CKR.CKR_DEVICE_ERROR)]
    [InlineData(CKR.CKR_HOST_MEMORY)]
    [InlineData(CKR.CKR_SLOT_ID_INVALID)]
    public void Detect_SlotInfoFails_FailsTheDerivation_AndAsksAgain(CKR error)
    {
        using var module = new Pbkd2Module(P11Kit);
        module.Slots[1] = (Mozilla, 3, 98);
        module.SlotInfoErrors.Enqueue(error);
        using var session = module.OpenSession(slot: 1);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => GenerateKey(session, "correct horse"u8));
        Assert.Equal(error, ex.ReturnValue);
        Assert.Null(module.SentByReference);
        Assert.Empty(module.LowLevel.Pbkdf2PasswordLengthByReferenceBySlot);

        GenerateKey(session, "correct horse"u8);
        Assert.True(module.SentByReference);
        Assert.Equal(2, module.GetSlotInfoCalls);
    }

    [Fact]
    public void Detect_GetInfoFails_FailsTheDerivation_AndAsksAgain()
    {
        using var module = new Pbkd2Module("Acme HSM", cryptokiMajor: 2, cryptokiMinor: 20);
        module.Slots[1] = ("Acme HSM", 5, 1);
        module.InfoErrors.Enqueue(CKR.CKR_DEVICE_ERROR);
        using var session = module.OpenSession(slot: 1);

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => GenerateKey(session, "correct horse"u8));
        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        Assert.Null(module.SentByReference);
        Assert.Empty(module.LowLevel.Pbkdf2PasswordLengthByReferenceBySlot);

        GenerateKey(session, "correct horse"u8);
        Assert.True(module.SentByReference);
    }

    /// <summary>A session not opened through a slot has none to ask about.</summary>
    [Fact]
    public void Detect_SessionWithoutASlot_GetsTheStandardStructure_WithoutAsking()
    {
        using var module = new Pbkd2Module(Mozilla, cryptokiMajor: 2, cryptokiMinor: 20);
        module.Slots[1] = (Mozilla, 3, 98);
        using var session = module.CreateSession(policy: CryptoPolicy.AllowInsecure);

        GenerateKey(session, "correct horse"u8);

        Assert.False(module.SentByReference);
        Assert.Equal(0, module.GetSlotInfoCalls);
        Assert.Equal(0, module.GetInfoCalls);
    }

    /// <summary>
    /// A wrong structure can take the process down with no exception, so the choice is logged before the
    /// first derivation on a slot.
    /// </summary>
    [Fact]
    public void Detect_LogsTheDecisionOncePerSlot()
    {
        var logger = new CapturingLogger();
        using var module = new Pbkd2Module(P11Kit);
        module.Slots[1] = (Mozilla, 3, 98);
        using var session = module.OpenSession(slot: 1, new CapturingLoggerFactory(logger));

        GenerateKey(session, "correct horse"u8);
        GenerateKey(session, "correct horse"u8);

        CapturingLogger.Entry entry = Assert.Single(logger.Entries, e => e.Message.Contains("CKM_PKCS5_PBKD2", StringComparison.Ordinal));
        Assert.Equal(LogLevel.Debug, entry.Level);
        Assert.Contains("CK_PKCS5_PBKD2_PARAMS to slot 1 (NSS 3.98)", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("correct horse", entry.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(SoftHsm, true)]
    [InlineData(Mozilla, false)]
    public void ConfiguredLayout_OverridesDetection_WithoutAsking(string slotManufacturer, bool byReference)
    {
        using var module = new Pbkd2Module(P11Kit, cryptokiMajor: 2, cryptokiMinor: 20);
        module.Slots[1] = (slotManufacturer, 3, 51);
        module.LowLevel.Pbkdf2PasswordLengthByReference = byReference;
        using var session = module.OpenSession(slot: 1);

        GenerateKey(session, "correct horse"u8);

        Assert.Equal(byReference, module.SentByReference);
        Assert.Equal("correct horse"u8.ToArray(), module.Password);
        Assert.Equal(0, module.GetInfoCalls);
        Assert.Equal(0, module.GetSlotInfoCalls);
    }

    /// <summary>An empty password still gets a length to point at, not a null pointer.</summary>
    [Fact]
    public void ByReference_EmptyPassword_PointsAtAZeroLength()
    {
        using var module = new Pbkd2Module(Mozilla);
        module.Slots[1] = (Mozilla, 3, 51);
        using var session = module.OpenSession(slot: 1);

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
        using var module = new Pbkd2Module(Mozilla);

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

    private static void GenerateKey(Pkcs11SessionCore session, ReadOnlySpan<byte> password)
    {
        var parameters = new CkmPkcs5Pbkd2Params(Salt, 1000, CKP.CKP_PKCS5_PBKD2_HMAC_SHA256, password);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();
        session.GenerateKey(new Mechanism(CKM.CKM_PKCS5_PBKD2, parameters), [.. template.Attributes]);
    }

    // Reports a manufacturer and Cryptoki version from C_GetInfo, or refuses it when the manufacturer is
    // null; reports the manufacturer and hardware version of each slot in Slots, and refuses
    // C_GetSlotInfo for any other; opens sessions on any slot; and records which layout each
    // CKM_PKCS5_PBKD2 call carried. Overrides v2.40 functions only, so it exports just C_GetFunctionList.
    private class Pbkd2Module(string? moduleManufacturer, byte cryptokiMajor = 3, byte cryptokiMinor = 0) : SessionTestModule
    {
        public Dictionary<ulong, (string Manufacturer, byte Major, byte Minor)> Slots { get; } = [];
        public int GetInfoCalls { get; private set; }
        public int GetSlotInfoCalls { get; private set; }

        /// <summary>Errors the next C_GetInfo calls return, before answering normally again.</summary>
        public Queue<CKR> InfoErrors { get; } = new();

        /// <summary>Errors the next C_GetSlotInfo calls return, before answering normally again.</summary>
        public Queue<CKR> SlotInfoErrors { get; } = new();

        public bool? SentByReference { get; private set; }
        public byte[]? Password { get; private set; }
        public byte[]? Salt { get; private set; }
        public ulong Iterations { get; private set; }

        /// <summary>A session on <paramref name="slot"/>, opened through <see cref="Pkcs11Slot"/> as an application does.</summary>
        public Pkcs11SessionCore OpenSession(ulong slot, ILoggerFactory? loggerFactory = null)
            => new Pkcs11Slot(LowLevel, slot, loggerFactory).OpenSessionCore(policy: CryptoPolicy.AllowInsecure);

        protected override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        {
            session = NewSessionHandle();
            return CKR.CKR_OK;
        }

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            GetInfoCalls++;
            if (InfoErrors.TryDequeue(out CKR error))
                return error;
            if (moduleManufacturer is null)
                return CKR.CKR_FUNCTION_NOT_SUPPORTED;
            info.CryptokiVersion = new CK_VERSION { Major = cryptokiMajor, Minor = cryptokiMinor };
            NativeTestStructs.FillPadded(info.ManufacturerId, moduleManufacturer);
            NativeTestStructs.FillPadded(info.LibraryDescription, "PBKDF2 layout test module");
            info.LibraryVersion = new CK_VERSION { Major = 1, Minor = 0 };
            return CKR.CKR_OK;
        }

        protected override CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
        {
            GetSlotInfoCalls++;
            if (SlotInfoErrors.TryDequeue(out CKR error))
                return error;
            if (!Slots.TryGetValue((ulong)slotId, out var slot))
                return CKR.CKR_FUNCTION_NOT_SUPPORTED;
            NativeTestStructs.FillPadded(info.SlotDescription, "PBKDF2 layout test slot");
            NativeTestStructs.FillPadded(info.ManufacturerId, slot.Manufacturer);
            info.HardwareVersion = new CK_VERSION { Major = slot.Major, Minor = slot.Minor };
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
    private sealed class V3Pbkd2Module(string moduleManufacturer) : Pbkd2Module(moduleManufacturer)
    {
        protected override CKR C_GetInterfaceList(bool listIsNull, Span<CK_INTERFACE> interfaces, ref NativeCULong count)
            => CKR.CKR_FUNCTION_NOT_SUPPORTED;
    }
}
