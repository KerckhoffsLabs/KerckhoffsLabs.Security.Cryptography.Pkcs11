using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native.Dispatch;

/// <summary>
/// The general-purpose wrappers (<c>C_Initialize</c>, <c>C_Finalize</c>, <c>C_GetInfo</c> and the v3.0
/// interface queries), called through a module's function table: each reaches the module and returns what
/// it writes, across the Windows struct packing, and the interface list refuses an over-reported count.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class GeneralDispatchTests
{
    private static readonly Dictionary<string, DispatchCase> Cases = new DispatchCase[]
    {
        new(nameof(LowLevelPkcs11Library.C_Initialize), l => l.C_Initialize(null)),
        new(nameof(LowLevelPkcs11Library.C_Finalize), l => l.C_Finalize(IntPtr.Zero)),
        new(nameof(LowLevelPkcs11Library.C_GetInfo), l =>
        {
            CK_INFO info = default;
            CKR rv = l.C_GetInfo(ref info);
            return rv == CKR.CKR_OK && (info.CryptokiVersion.Major != 3 || info.CryptokiVersion.Minor != 2) ? CKR.CKR_GENERAL_ERROR : rv;
        }),
        new(nameof(LowLevelPkcs11Library.C_GetInterfaceList), l =>
        {
            var interfaces = new CK_INTERFACE[2];
            NativeCULong count = (NativeCULong)2;
            CKR rv = l.C_GetInterfaceList(interfaces, ref count);
            return rv == CKR.CKR_OK && ((ulong)count != 1 || (ulong)interfaces[0].Flags != 1) ? CKR.CKR_GENERAL_ERROR : rv;
        }),
    }.ToDictionary(c => c.Function, StringComparer.Ordinal);

    public static TheoryData<string> Functions => [.. Cases.Keys];

    // A FakeModule binds C_Initialize and C_Finalize unless built without them (see
    // InitializeAndFinalize_OfAModuleWithoutThem_ReturnNotSupported), so only these are left out of an
    // otherwise empty module's table.
    public static TheoryData<string> OptionalFunctions =>
        [nameof(LowLevelPkcs11Library.C_GetInfo), nameof(LowLevelPkcs11Library.C_GetInterfaceList), nameof(LowLevelPkcs11Library.C_GetInterface)];

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_ReachesTheModule_AndReturnsWhatItWrites(string function)
    {
        using var module = new GeneralModule();
        Assert.Equal(CKR.CKR_OK, DispatchSmoke.ReachesTheModule(module, Cases[function]));
    }

    [Theory]
    [MemberData(nameof(OptionalFunctions))]
    public void Wrapper_OfAFunctionTheModuleLacks_ReturnsNotSupported(string function)
        => DispatchSmoke.ReportsAMissingFunctionUnsupported(function == nameof(LowLevelPkcs11Library.C_GetInterface) ? GetInterfaceCase : Cases[function]);

    [Theory]
    [MemberData(nameof(Functions))]
    public void Wrapper_AfterDispose_Throws_WithoutReachingTheModule(string function)
    {
        using var module = new GeneralModule();
        DispatchSmoke.RefusesACallAfterDispose(module, Cases[function]);
    }

    // The module's own interface, reached through the C_GetInterface slot of the table it handed out.
    [Fact]
    public void GetInterface_ReturnsTheModulesInterface()
    {
        using var module = new GeneralModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Equal(CKR.CKR_OK, GetInterfaceCase.Invoke(lowLevel));
    }

    [Fact]
    public void GetInterfaceList_CountQuery_SendsNoList()
    {
        using var module = new GeneralModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        NativeCULong count = default;

        Assert.Equal(CKR.CKR_OK, lowLevel.C_GetInterfaceList(null, ref count));

        Assert.True(module.ListWasNull);
        Assert.Equal(1UL, (ulong)count);
    }

    [Fact]
    public void GetInterfaceList_ReportingMoreThanTheListHolds_IsRefused()
    {
        using var module = new GeneralModule { OverReports = true };
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        NativeCULong count = (NativeCULong)2;

        Assert.Throws<Pkcs11UnclassifiedException>(() => lowLevel.C_GetInterfaceList(new CK_INTERFACE[2], ref count));
    }

    [Fact]
    public void InitializeAndFinalize_OfAModuleWithoutThem_ReturnNotSupported()
    {
        using var module = new NoLifecycleModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, lowLevel.C_Initialize(null));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, lowLevel.C_Finalize(IntPtr.Zero));
        Assert.DoesNotContain(module.Calls.Keys, name => name != "C_GetFunctionList");
    }

    // An empty list is a real (zero-entry) list, not the NULL of a count query: the module answers
    // CKR_BUFFER_TOO_SMALL with the count, rather than CKR_OK with a count the empty list cannot hold.
    [Fact]
    public void GetInterfaceList_IntoAnEmptyList_SendsAListAndReturnsBufferTooSmall()
    {
        using var module = new GeneralModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        NativeCULong count = default;

        Assert.Equal(CKR.CKR_BUFFER_TOO_SMALL, lowLevel.C_GetInterfaceList([], ref count));

        Assert.False(module.ListWasNull);
        Assert.Equal(1UL, (ulong)count);
    }

    private static readonly DispatchCase GetInterfaceCase = new(nameof(LowLevelPkcs11Library.C_GetInterface), l =>
    {
        CKR rv = l.C_GetInterface("PKCS 11\0"u8, (NativeCULong)0, out CK_INTERFACE iface);
        return rv == CKR.CKR_OK && iface.FunctionList == IntPtr.Zero ? CKR.CKR_GENERAL_ERROR : rv;
    });

    /// <summary>A module whose table has no <c>C_Initialize</c> or <c>C_Finalize</c>.</summary>
    private sealed class NoLifecycleModule() : FakeModule(bindsLifecycle: false);

    /// <summary>A v3.2 module (it implements <c>C_GetInterfaceList</c>) that answers the general queries.</summary>
    private sealed class GeneralModule : FakeModule
    {
        public bool OverReports { get; init; }
        public bool ListWasNull { get; private set; }

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            info.CryptokiVersion = new CK_VERSION { Major = 3, Minor = 2 };
            return CKR.CKR_OK;
        }

        protected override CKR C_GetInterfaceList(bool listIsNull, Span<CK_INTERFACE> interfaces, ref NativeCULong count)
        {
            ListWasNull = listIsNull;
            if (!listIsNull && interfaces.IsEmpty)
            {
                count = (NativeCULong)1;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }
            if (!listIsNull)
                interfaces[0] = new CK_INTERFACE { Flags = (NativeCULong)1 };
            count = (NativeCULong)(ulong)(OverReports ? interfaces.Length + 1 : 1);
            return CKR.CKR_OK;
        }
    }
}
