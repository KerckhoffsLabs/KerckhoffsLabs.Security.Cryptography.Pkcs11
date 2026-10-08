using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Hermetic tests for the real native function-list loader: the version dispatch and
/// table read in <see cref="LowLevelPkcs11Library.LoadTable(Func{string, IntPtr})"/> — the one code path that can corrupt the process — used
/// to be reachable only through a real PKCS#11 module. These tests drive it with no native
/// module at all: an export resolver hands the loader <c>[UnmanagedCallersOnly]</c> managed
/// stubs for <c>C_GetFunctionList</c>/<c>C_GetInterface</c>, whose tables live in unmanaged
/// memory with a unique sentinel pointer in every slot. After construction, reflection reads each
/// same-named <see cref="CryptokiTable"/> slot and asserts the sentinel landed there — a slot copied
/// from the wrong place fails by name.
/// </summary>
/// <remarks>
/// <para>
/// The tables are written at the offsets <see cref="CryptokiTable"/> reads (see <see cref="NativeFunctionList"/>),
/// so a wrong offset would round-trip unnoticed here. Those offsets, and the slot order, are checked
/// against the C compiler's layout of the OASIS headers by <see cref="AbiOracleTests"/>.
/// </para>
/// <para>
/// Static fields feed the <c>[UnmanagedCallersOnly]</c> stubs (which cannot capture state), and
/// are written only through <c>InstallModule</c>. xUnit serializes tests within a class, so the
/// statics are race-free. Sentinels are never invoked — the loader only calls the two bootstrap
/// functions, which are real managed stubs.
/// </para>
/// </remarks>
public sealed unsafe class TableLoaderTests : IDisposable
{
    // ---------------------------------------------------------------------------
    // Fake module: bootstrap stubs + synthetic tables
    // ---------------------------------------------------------------------------

    private static IntPtr s_functionListPtr;   // handed out by FakeGetFunctionList
    private static IntPtr s_interfacePtr;      // handed out by FakeGetInterface for the default interface
    private static uint s_getInterfaceRv;      // CKR FakeGetInterface returns
    private static Dictionary<(byte Major, byte Minor), IntPtr>? s_versioned; // null: requested version ignored

    private readonly List<IntPtr> _allocations = [];

    public void Dispose()
    {
        foreach (IntPtr p in _allocations) Marshal.FreeHGlobal(p);
        _allocations.Clear();
        InstallModule(IntPtr.Zero);
    }

    /// <summary>
    /// Publishes the module state that <see cref="FakeGetFunctionList"/> and
    /// <see cref="FakeGetInterface"/> will hand back, and resets what is not given.
    /// </summary>
    /// <remarks>
    /// Static, and the only writer of these fields. The stubs are
    /// <c>[UnmanagedCallersOnly]</c> and so cannot capture instance state — reaching statics is the
    /// only channel available to them — which makes the coupling unavoidable rather than incidental.
    /// Routing every write through one named method keeps it stated in a single place instead of
    /// scattered field-by-field across each test, and keeps the tests reading as "install this
    /// module, then load it".
    /// </remarks>
    /// <param name="functionList">Table <c>C_GetFunctionList</c> hands out.</param>
    /// <param name="interfaceTable">Table <c>C_GetInterface</c> hands out; none by default.</param>
    /// <param name="getInterfaceRv">CKR <c>C_GetInterface</c> returns; <c>CKR_OK</c> by default.</param>
    /// <param name="versioned">
    /// Interfaces served for a requested version; any other requested version is refused
    /// (<c>CKR_ARGUMENTS_BAD</c>). <see langword="null"/> (the default) models a module that ignores the
    /// requested version and always hands back <paramref name="interfaceTable"/>.
    /// </param>
    private static void InstallModule(
        IntPtr functionList, IntPtr interfaceTable = default, uint getInterfaceRv = 0,
        Dictionary<(byte Major, byte Minor), IntPtr>? versioned = null)
    {
        s_functionListPtr = functionList;
        s_interfacePtr = interfaceTable;
        s_getInterfaceRv = getInterfaceRv;
        s_versioned = versioned;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong FakeGetFunctionList(IntPtr* ppFunctionList)
    {
        *ppFunctionList = s_functionListPtr;
        return new NativeCULong(0); // CKR_OK
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static NativeCULong FakeGetInterface(byte* pInterfaceName, IntPtr pVersion, IntPtr* ppInterface, NativeCULong flags)
    {
        if (pVersion != IntPtr.Zero && s_versioned is not null)
        {
            CK_VERSION wanted = *(CK_VERSION*)pVersion;
            if (!s_versioned.TryGetValue((wanted.Major, wanted.Minor), out IntPtr served))
                return new NativeCULong(0x00000007); // CKR_ARGUMENTS_BAD
            *ppInterface = served;
            return new NativeCULong(0);
        }
        *ppInterface = s_interfacePtr;
        return new NativeCULong(s_getInterfaceRv);
    }

    private static IntPtr GetFunctionListStub
        => (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)&FakeGetFunctionList;

    private static IntPtr GetInterfaceStub
        => (IntPtr)(delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)&FakeGetInterface;

    private IntPtr Alloc(int size)
    {
        IntPtr p = Marshal.AllocHGlobal(size);
        _allocations.Add(p);
        return p;
    }

    /// <summary>
    /// Builds a function-list table of <paramref name="slotCount"/> slots in unmanaged memory, assigning a
    /// unique sentinel pointer to every slot (offset by <paramref name="sentinelBase"/> so distinct tables
    /// never share a sentinel), and returns the table pointer plus the slot-name → sentinel map.
    /// </summary>
    private (IntPtr Table, Dictionary<string, IntPtr> Sentinels) BuildTable(byte major, byte minor, int slotCount, long sentinelBase)
    {
        var sentinels = new Dictionary<string, IntPtr>();
        for (int i = 0; i < slotCount; i++)
            sentinels[NativeFunctionList.SlotNames[i]] = (IntPtr)(sentinelBase + (i + 1) * 0x10);

        IntPtr table = Alloc(NativeFunctionList.SizeOf(slotCount));
        NativeFunctionList.Write(table, major, minor, slotCount, sentinels);
        return (table, sentinels);
    }

    /// <summary>Builds the CK_INTERFACE descriptor C_GetInterface hands back.</summary>
    private IntPtr BuildInterface(IntPtr functionList)
    {
        var iface = new CK_INTERFACE { InterfaceName = IntPtr.Zero, FunctionList = functionList, Flags = new NativeCULong(0) };
        IntPtr p = Alloc(Marshal.SizeOf<CK_INTERFACE>() + 16);
        UnmanagedMemory.Write(p, in iface);
        return p;
    }

    private static Func<string, IntPtr> Resolver(Dictionary<string, IntPtr> exports)
        => name => exports.TryGetValue(name, out IntPtr p) ? p : IntPtr.Zero;

    // ---------------------------------------------------------------------------
    // Reflection bridge to the CryptokiTable
    // ---------------------------------------------------------------------------

    private static IntPtr Fp(CryptokiTable loaded, string name)
    {
        FieldInfo? field = typeof(CryptokiTable).GetField(name, BindingFlags.Instance | BindingFlags.Public);
        Assert.NotNull(field);
        // Function-pointer fields box as IntPtr under reflection.
        return (IntPtr)field!.GetValue(loaded)!;
    }

    private static bool FpFieldExists(string name)
        => typeof(CryptokiTable).GetField(name, BindingFlags.Instance | BindingFlags.Public) is not null;

    private static IEnumerable<string> SlotNames(int slotCount) => NativeFunctionList.SlotNames.Take(slotCount);

    private static IEnumerable<string> V30AdditionNames()
        => SlotNames(CryptokiTable.V30SlotCount).Skip(CryptokiTable.V240SlotCount);

    private static IEnumerable<string> V32AdditionNames()
        => SlotNames(CryptokiTable.V32SlotCount).Skip(CryptokiTable.V30SlotCount);

    /// <summary>
    /// Asserts that for every slot in <paramref name="expected"/> (minus <paramref name="skip"/>),
    /// the same-named <see cref="CryptokiTable"/> slot carries exactly that table's sentinel.
    /// </summary>
    private static void AssertBoundTo(CryptokiTable loaded, Dictionary<string, IntPtr> expected, params string[] skip)
    {
        foreach ((string name, IntPtr sentinel) in expected)
        {
            if (skip.Contains(name)) continue;
            Assert.True(FpFieldExists(name), $"CryptokiTable has no slot '{name}'.");
            Assert.True(Fp(loaded, name) == sentinel, $"Slot '{name}' bound to 0x{Fp(loaded, name):X}, expected sentinel 0x{sentinel:X}.");
        }
    }

    private static void AssertAllZero(CryptokiTable loaded, IEnumerable<string> names, params string[] skip)
    {
        foreach (string name in names.Where(n => !skip.Contains(n) && FpFieldExists(n)))
            Assert.True(Fp(loaded, name) == IntPtr.Zero, $"Slot '{name}' should be unbound but is 0x{Fp(loaded, name):X}.");
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    // ReleaseHandle can run on the finalizer thread, where nothing may throw. A module whose table leaves
    // C_Finalize unbound must still be released cleanly, without calling into the empty slot.
    [Fact]
    public void ModuleWithoutC_Finalize_IsReleasedWithoutThrowing()
    {
        var (table, sentinels) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        sentinels.Remove("C_Finalize");
        NativeFunctionList.Write(table, 2, 40, CryptokiTable.V240SlotCount, sentinels);
        InstallModule(table);

        var module = Pkcs11ModuleHandle.Bind(() => LowLevelPkcs11Library.LoadTable(Resolver(new() { ["C_GetFunctionList"] = GetFunctionListStub })));
        Assert.True(module.Table.C_Finalize is null);
        module.MarkInitialized(osLocking: true);
        module.FinalizeOnRelease();

        module.Dispose();

        Assert.True(module.IsClosed);
    }

    [Fact]
    public void V240Module_BindsEveryBaseSlot_AndLeavesV3SurfaceNull()
    {
        var (table, sentinels) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        InstallModule(table);

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new() { ["C_GetFunctionList"] = GetFunctionListStub }));

        // Every v2.40 slot must land in the same-named table slot.
        AssertBoundTo(loaded, sentinels);
        // No v3.0/v3.2 surface: there is no interface table to take it from.
        AssertAllZero(loaded, V30AdditionNames());
        AssertAllZero(loaded, V32AdditionNames());
    }

    // v3.x functions come only from the interface table: exports without one bind nothing, since a
    // per-symbol lookup can resolve another module's function and mixes tables (PKCS#11 v3.0 §5.4).
    [Fact]
    public void V240Module_PerSymbolExports_AreNotBound()
    {
        var (table, baseSentinels) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        InstallModule(table);
        IntPtr loginUser = (IntPtr)0x0BAD_0010;
        IntPtr encapsulate = (IntPtr)0x0BAD_0020;

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_LoginUser"] = loginUser,
            ["C_EncapsulateKey"] = encapsulate,
        }));

        AssertBoundTo(loaded, baseSentinels);
        AssertAllZero(loaded, V30AdditionNames());
        AssertAllZero(loaded, V32AdditionNames());
    }

    [Fact]
    public void V30Interface_BindsV30Additions_FromInterfaceTable()
    {
        var (baseTable, baseSentinels) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        var (v30Table, v30Sentinels) = BuildTable(3, 0, CryptokiTable.V30SlotCount, 0x0B00_0000);
        InstallModule(baseTable, BuildInterface(v30Table));  // getInterfaceRv defaults to CKR_OK

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        // v3.0 additions come from the interface table — C_GetInterface's slot included: the export
        // is only the bootstrap that found the table.
        var v30Additions = V30AdditionNames().ToHashSet();
        AssertBoundTo(loaded, v30Sentinels.Where(kv => v30Additions.Contains(kv.Key)).ToDictionary());

        // One table source: the base slots come from the interface table too, not C_GetFunctionList's.
        AssertBoundTo(loaded, v30Sentinels, "C_GetInterface");
        Assert.NotEqual(baseSentinels["C_Initialize"], Fp(loaded, "C_Initialize"));

        // version {3,0} must NOT trigger the v3.2 re-read.
        AssertAllZero(loaded, V32AdditionNames());
    }

    /// <summary>
    /// <see cref="LowLevelPkcs11Library.IsV32ApiSupported"/> needs every one of the v3.2 functions it
    /// names. A module whose v3.2 table leaves one of them out must not be reported as having the v3.2
    /// surface, or a caller told it does would reach a function that is not there.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("C_EncapsulateKey")]
    [InlineData("C_DecapsulateKey")]
    [InlineData("C_WrapKeyAuthenticated")]
    [InlineData("C_UnwrapKeyAuthenticated")]
    [InlineData("C_VerifySignatureInit")]
    [InlineData("C_VerifySignature")]
    [InlineData("C_GetSessionValidationFlags")]
    public void IsV32ApiSupported_RequiresEveryV32Function(string? missing)
    {
        var (table, sentinels) = BuildTable(3, 2, CryptokiTable.V32SlotCount, 0x0C00_0000);
        if (missing is not null)
        {
            Assert.True(sentinels.Remove(missing), $"{missing} is not a slot of the v3.2 table");
            NativeFunctionList.Write(table, 3, 2, CryptokiTable.V32SlotCount, sentinels);
        }
        InstallModule(table, BuildInterface(table));

        using var lowLevel = new LowLevelPkcs11Library(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        Assert.Equal(missing is null, lowLevel.IsV32ApiSupported);
    }

    [Fact]
    public void V32Interface_BindsV30AndV32Additions_FromInterfaceTable()
    {
        var (baseTable, _) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        var (v32Table, v32Sentinels) = BuildTable(3, 2, CryptokiTable.V32SlotCount, 0x0C00_0000);
        InstallModule(baseTable, BuildInterface(v32Table));

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        var additions = V30AdditionNames().Concat(V32AdditionNames()).ToHashSet();
        AssertBoundTo(
            loaded,
            v32Sentinels.Where(kv => additions.Contains(kv.Key)).ToDictionary(),
            "C_GetInterface");
        // One table source: base slots from the same v3.2 table.
        AssertBoundTo(loaded, v32Sentinels, "C_GetInterface");
    }

    // A module whose default interface is 3.0 but which also offers 3.2 gets the 3.2 surface: each
    // known version is requested before the default is taken.
    [Fact]
    public void DefaultInterfaceIs30_ButServes32OnRequest_Binds32()
    {
        var (baseTable, _) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        var (v30Table, _) = BuildTable(3, 0, CryptokiTable.V30SlotCount, 0x0B00_0000);
        var (v32Table, v32Sentinels) = BuildTable(3, 2, CryptokiTable.V32SlotCount, 0x0C00_0000);
        InstallModule(baseTable, BuildInterface(v30Table), versioned: new()
        {
            [(3, 0)] = BuildInterface(v30Table),
            [(3, 2)] = BuildInterface(v32Table),
        });

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        AssertBoundTo(loaded, v32Sentinels, "C_GetInterface");
    }

    // A table is believed only if its header is the version requested: a {3,0} table handed back for a
    // {3,2} request must not be read as 3.2, which would read past its end.
    [Fact]
    public void TableWhoseHeaderIsNotTheRequestedVersion_IsNotReadAsThatVersion()
    {
        var (baseTable, _) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        var (v30Table, v30Sentinels) = BuildTable(3, 0, CryptokiTable.V30SlotCount, 0x0B00_0000);
        InstallModule(baseTable, versioned: new()
        {
            [(3, 2)] = BuildInterface(v30Table), // lies: header says {3,0}
            [(3, 0)] = BuildInterface(v30Table),
        });

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        AssertBoundTo(loaded, v30Sentinels, "C_GetInterface");
        AssertAllZero(loaded, V32AdditionNames());
    }

    // Some modules answer only the NULL/NULL request: the default interface is then bound by its header.
    [Fact]
    public void EveryExactRequestRefused_DefaultInterfaceIsBoundByItsHeader()
    {
        var (baseTable, _) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        var (v32Table, v32Sentinels) = BuildTable(3, 2, CryptokiTable.V32SlotCount, 0x0C00_0000);
        InstallModule(baseTable, BuildInterface(v32Table), versioned: []);

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        AssertBoundTo(loaded, v32Sentinels, "C_GetInterface");
    }

    // A later 3.x than this library knows extends the 3.0 table; only that prefix is read.
    [Fact]
    public void DefaultInterfaceOfAnUnknown3x_BindsOnlyThe30Prefix()
    {
        var (baseTable, _) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        var (v33Table, v33Sentinels) = BuildTable(3, 3, CryptokiTable.V32SlotCount, 0x0C00_0000);
        InstallModule(baseTable, BuildInterface(v33Table), versioned: []);

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        var v30Slots = SlotNames(CryptokiTable.V30SlotCount).ToHashSet();
        AssertBoundTo(loaded, v33Sentinels.Where(kv => v30Slots.Contains(kv.Key)).ToDictionary(), "C_GetInterface");
        AssertAllZero(loaded, V32AdditionNames());
    }

    [Fact]
    public void InterfaceWithANullFunctionList_FallsBackToGetFunctionList()
    {
        var (baseTable, baseSentinels) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        InstallModule(baseTable, BuildInterface(IntPtr.Zero));

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        AssertBoundTo(loaded, baseSentinels);
        AssertAllZero(loaded, V30AdditionNames(), "C_GetInterface");
    }

    [Fact]
    public void Interface_ReportingV240Version_BindsNoV3Surface()
    {
        var (baseTable, baseSentinels) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        var (v30Table, _) = BuildTable(2, 40, CryptokiTable.V30SlotCount, 0x0B00_0000); // header says 2.40
        InstallModule(baseTable, BuildInterface(v30Table));
        IntPtr sessionCancel = (IntPtr)0x0BAD_0030;

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
            ["C_SessionCancel"] = sessionCancel,
        }));

        // The sub-3.0 version header rejects the interface table, and the export is not a substitute.
        AssertAllZero(loaded, V30AdditionNames(), "C_GetInterface");
        AssertBoundTo(loaded, baseSentinels);
    }

    [Fact]
    public void Interface_ReturningError_BindsNoV3Surface()
    {
        var (baseTable, baseSentinels) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        InstallModule(baseTable, getInterfaceRv: 0x00000006);  // CKR_FUNCTION_FAILED
        IntPtr loginUser = (IntPtr)0x0BAD_0040;

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
            ["C_LoginUser"] = loginUser,
        }));

        AssertAllZero(loaded, V30AdditionNames(), "C_GetInterface");
        AssertBoundTo(loaded, baseSentinels);
    }

    [Fact]
    public void NullSlotsInV32Table_StayUnbound()
    {
        var (baseTable, _) = BuildTable(2, 40, CryptokiTable.V240SlotCount, 0x0A00_0000);
        // A v3.2 table with EVERY slot null: every slot must copy as null, not as garbage, and nothing
        // may throw.
        IntPtr v32Table = Alloc(NativeFunctionList.SizeOf(CryptokiTable.V32SlotCount));
        NativeFunctionList.Write(v32Table, 3, 2, CryptokiTable.V32SlotCount, new Dictionary<string, IntPtr>());
        InstallModule(baseTable, BuildInterface(v32Table));

        CryptokiTable loaded = LowLevelPkcs11Library.LoadTable(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        AssertAllZero(loaded, V30AdditionNames(), "C_GetInterface");
        AssertAllZero(loaded, V32AdditionNames());
    }

    [Fact]
    public void MissingGetFunctionList_ThrowsEntryPointNotFound()
        => Assert.Throws<EntryPointNotFoundException>(() => LowLevelPkcs11Library.LoadTable(Resolver([])));

    [Fact]
    public void SlotName_Coverage_SanityCheck()
    {
        // Guards the test harness itself: the table must expose the expected slot populations, or the
        // reflection sweep would silently assert nothing.
        Assert.Equal(CryptokiTable.V32SlotCount, NativeFunctionList.SlotNames.Count);
        Assert.Equal(24, V30AdditionNames().Count());
        Assert.Equal(12, V32AdditionNames().Count());
    }
}
