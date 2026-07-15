using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// Hermetic tests for the real native function-list loader: the version dispatch and
/// pointer binding in <c>Delegates</c> — the one code path that can corrupt the process — used
/// to be reachable only through a real PKCS#11 module. These tests drive it with no native
/// module at all: an export resolver hands the loader <c>[UnmanagedCallersOnly]</c> managed
/// stubs for <c>C_GetFunctionList</c>/<c>C_GetInterface</c>, whose tables live in unmanaged
/// memory with a unique sentinel pointer in every slot. After construction, reflection maps
/// each <c>CK_FUNCTION_LIST*</c> field to its same-named <see cref="FunctionPointers"/> field
/// (and <c>_Windows</c> sibling) and asserts the sentinel landed in the right slot — a
/// transposed field in the struct or a mis-wired binding line fails by name.
/// </summary>
/// <remarks>
/// Static fields feed the <c>[UnmanagedCallersOnly]</c> stubs (which cannot capture state).
/// xUnit serializes tests within a class, so the statics are race-free. Sentinels are never
/// invoked — the loader only calls the two bootstrap functions, which are real managed stubs.
/// </remarks>
public sealed unsafe class DelegatesLoaderTests : IDisposable
{
    // ---------------------------------------------------------------------------
    // Fake module: bootstrap stubs + synthetic tables
    // ---------------------------------------------------------------------------

    private static IntPtr s_functionListPtr;   // handed out by FakeGetFunctionList
    private static IntPtr s_interfacePtr;      // handed out by FakeGetInterface
    private static uint s_getInterfaceRv;      // CKR FakeGetInterface returns

    private readonly List<IntPtr> _allocations = [];

    public void Dispose()
    {
        foreach (IntPtr p in _allocations) Marshal.FreeHGlobal(p);
        _allocations.Clear();
        s_functionListPtr = IntPtr.Zero;
        s_interfacePtr = IntPtr.Zero;
        s_getInterfaceRv = 0;
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
    /// Builds a <typeparamref name="T"/> function-list table in unmanaged memory, assigning a
    /// unique sentinel pointer to every <see cref="IntPtr"/> slot (offset by
    /// <paramref name="sentinelBase"/> so distinct tables never share a sentinel), and returns
    /// the table pointer plus the slot-name → sentinel map. Written through the same
    /// packed-struct dispatch the loader reads with, so the round-trip holds on every platform.
    /// </summary>
    private (IntPtr Table, Dictionary<string, IntPtr> Sentinels) BuildTable<T>(byte major, byte minor, long sentinelBase)
        where T : struct
    {
        object boxed = default(T);
        var sentinels = new Dictionary<string, IntPtr>();
        int i = 0;
        foreach (FieldInfo field in typeof(T).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public))
        {
            if (field.FieldType == typeof(IntPtr))
            {
                IntPtr sentinel = (IntPtr)(sentinelBase + ++i * 0x10);
                field.SetValue(boxed, sentinel);
                sentinels[field.Name] = sentinel;
            }
            else if (field.FieldType == typeof(CK_VERSION))
            {
                field.SetValue(boxed, new CK_VERSION { Major = major, Minor = minor });
            }
        }
        Assert.NotEmpty(sentinels); // the table type must actually carry function-pointer slots

        IntPtr table = Alloc(Marshal.SizeOf<T>() + 64); // slack: packed size never exceeds Marshal size
        WriteTable(table, (T)boxed);
        return (table, sentinels);
    }

    private static void WriteTable<T>(IntPtr memory, in T value) where T : struct
        => UnmanagedMemory.Write(memory, in value);

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
    // Reflection bridge to the FunctionPointers table
    // ---------------------------------------------------------------------------

    private static IntPtr Fp(Delegates delegates, string name)
    {
        FieldInfo? field = typeof(FunctionPointers).GetField(name, BindingFlags.Instance | BindingFlags.Public);
        Assert.NotNull(field);
        // Function-pointer fields box as IntPtr under reflection.
        return (IntPtr)field!.GetValue(delegates._fp)!;
    }

    private static bool FpFieldExists(string name)
        => typeof(FunctionPointers).GetField(name, BindingFlags.Instance | BindingFlags.Public) is not null;

    private static IEnumerable<string> SlotNames<T>() where T : struct
        => typeof(T).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)
            .Where(f => f.FieldType == typeof(IntPtr))
            .Select(f => f.Name);

    private static IEnumerable<string> V30AdditionNames()
        => SlotNames<CK_FUNCTION_LIST_3_0>().Except(SlotNames<CK_FUNCTION_LIST>());

    private static IEnumerable<string> V32AdditionNames()
        => SlotNames<CK_FUNCTION_LIST_3_2>().Except(SlotNames<CK_FUNCTION_LIST_3_0>());

    /// <summary>
    /// Asserts that for every slot in <paramref name="expected"/> (minus <paramref name="skip"/>),
    /// the same-named <see cref="FunctionPointers"/> field — and its <c>_Windows</c> sibling when
    /// one exists — carries exactly that table's sentinel.
    /// </summary>
    private static void AssertBoundTo(Delegates delegates, Dictionary<string, IntPtr> expected, params string[] skip)
    {
        foreach ((string name, IntPtr sentinel) in expected)
        {
            if (skip.Contains(name)) continue;
            Assert.True(FpFieldExists(name), $"FunctionPointers has no field for table slot '{name}'.");
            Assert.True(Fp(delegates, name) == sentinel, $"Slot '{name}' bound to 0x{Fp(delegates, name):X}, expected sentinel 0x{sentinel:X}.");
            if (FpFieldExists(name + "_Windows"))
                Assert.True(Fp(delegates, name + "_Windows") == sentinel, $"Slot '{name}_Windows' not bound to its unified sentinel.");
        }
    }

    private static void AssertAllZero(Delegates delegates, IEnumerable<string> names, params string[] skip)
    {
        foreach (string name in names)
        {
            if (skip.Contains(name) || !FpFieldExists(name)) continue;
            Assert.True(Fp(delegates, name) == IntPtr.Zero, $"Slot '{name}' should be unbound but is 0x{Fp(delegates, name):X}.");
        }
    }

    // ---------------------------------------------------------------------------
    // Tests
    // ---------------------------------------------------------------------------

    [Fact]
    public void V240Module_BindsEveryBaseSlot_AndLeavesV3SurfaceNull()
    {
        var (table, sentinels) = BuildTable<CK_FUNCTION_LIST>(2, 40, 0x0A00_0000);
        s_functionListPtr = table;

        var delegates = new Delegates(Resolver(new() { ["C_GetFunctionList"] = GetFunctionListStub }));

        // Every v2.40 slot must land in the same-named dispatch field (and _Windows sibling).
        AssertBoundTo(delegates, sentinels);
        // No v3.0/v3.2 surface: neither the interface path nor the per-symbol fallback found anything.
        AssertAllZero(delegates, V30AdditionNames());
        AssertAllZero(delegates, V32AdditionNames());
    }

    [Fact]
    public void V240Module_PerSymbolExports_BindV30SurfaceWithoutGetInterface()
    {
        var (table, baseSentinels) = BuildTable<CK_FUNCTION_LIST>(2, 40, 0x0A00_0000);
        s_functionListPtr = table;
        IntPtr loginUser = (IntPtr)0x0BAD_0010;
        IntPtr encapsulate = (IntPtr)0x0BAD_0020;

        var delegates = new Delegates(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_LoginUser"] = loginUser,
            ["C_EncapsulateKey"] = encapsulate,
        }));

        AssertBoundTo(delegates, baseSentinels);
        Assert.Equal(loginUser, Fp(delegates, "C_LoginUser"));
        Assert.Equal(encapsulate, Fp(delegates, "C_EncapsulateKey"));
        Assert.Equal(encapsulate, Fp(delegates, "C_EncapsulateKey_Windows"));
        // Fallback bound only what the resolver exposed.
        AssertAllZero(delegates, V30AdditionNames(), "C_LoginUser");
        AssertAllZero(delegates, V32AdditionNames(), "C_EncapsulateKey");
    }

    [Fact]
    public void V30Interface_BindsV30Additions_FromInterfaceTable()
    {
        var (baseTable, baseSentinels) = BuildTable<CK_FUNCTION_LIST>(2, 40, 0x0A00_0000);
        var (v30Table, v30Sentinels) = BuildTable<CK_FUNCTION_LIST_3_0>(3, 0, 0x0B00_0000);
        s_functionListPtr = baseTable;
        s_interfacePtr = BuildInterface(v30Table);
        s_getInterfaceRv = 0; // CKR_OK

        var delegates = new Delegates(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        // v3.0 additions come from the interface table. C_GetInterface itself is bound to the
        // bootstrap stub (the loader binds the export, not the table slot) — skip it.
        var v30Additions = V30AdditionNames().ToHashSet();
        AssertBoundTo(
            delegates,
            v30Sentinels.Where(kv => v30Additions.Contains(kv.Key)).ToDictionary(),
            "C_GetInterface");
        Assert.Equal(GetInterfaceStub, Fp(delegates, "C_GetInterface"));

        // Base v2.40 slots stay bound from the C_GetFunctionList table (current, documented
        // behavior: the base surface is deliberately not re-sourced from the interface table).
        AssertBoundTo(delegates, baseSentinels);

        // version {3,0} must NOT trigger the v3.2 re-read.
        AssertAllZero(delegates, V32AdditionNames());
    }

    [Fact]
    public void V32Interface_BindsV30AndV32Additions_FromInterfaceTable()
    {
        var (baseTable, baseSentinels) = BuildTable<CK_FUNCTION_LIST>(2, 40, 0x0A00_0000);
        var (v32Table, v32Sentinels) = BuildTable<CK_FUNCTION_LIST_3_2>(3, 2, 0x0C00_0000);
        s_functionListPtr = baseTable;
        s_interfacePtr = BuildInterface(v32Table);
        s_getInterfaceRv = 0;

        var delegates = new Delegates(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        var additions = V30AdditionNames().Concat(V32AdditionNames()).ToHashSet();
        AssertBoundTo(
            delegates,
            v32Sentinels.Where(kv => additions.Contains(kv.Key)).ToDictionary(),
            "C_GetInterface");
        AssertBoundTo(delegates, baseSentinels);
    }

    [Fact]
    public void Interface_ReportingV240Version_FallsBackToPerSymbolLookup()
    {
        var (baseTable, baseSentinels) = BuildTable<CK_FUNCTION_LIST>(2, 40, 0x0A00_0000);
        var (v30Table, _) = BuildTable<CK_FUNCTION_LIST_3_0>(2, 40, 0x0B00_0000); // header says 2.40
        s_functionListPtr = baseTable;
        s_interfacePtr = BuildInterface(v30Table);
        s_getInterfaceRv = 0;
        IntPtr sessionCancel = (IntPtr)0x0BAD_0030;

        var delegates = new Delegates(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
            ["C_SessionCancel"] = sessionCancel,
        }));

        // The sub-3.0 version header rejects the interface table; per-symbol fallback runs.
        Assert.Equal(sessionCancel, Fp(delegates, "C_SessionCancel"));
        AssertAllZero(delegates, V30AdditionNames(), "C_SessionCancel", "C_GetInterface");
        AssertBoundTo(delegates, baseSentinels);
    }

    [Fact]
    public void Interface_ReturningError_FallsBackToPerSymbolLookup()
    {
        var (baseTable, baseSentinels) = BuildTable<CK_FUNCTION_LIST>(2, 40, 0x0A00_0000);
        s_functionListPtr = baseTable;
        s_interfacePtr = IntPtr.Zero;
        s_getInterfaceRv = 0x00000006; // CKR_FUNCTION_FAILED
        IntPtr loginUser = (IntPtr)0x0BAD_0040;

        var delegates = new Delegates(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
            ["C_LoginUser"] = loginUser,
        }));

        Assert.Equal(loginUser, Fp(delegates, "C_LoginUser"));
        AssertBoundTo(delegates, baseSentinels);
    }

    [Fact]
    public void NullSlotsInV32Table_StayUnbound()
    {
        var (baseTable, _) = BuildTable<CK_FUNCTION_LIST>(2, 40, 0x0A00_0000);
        // A v3.2 table with EVERY slot null: the bind guards must leave every fp null rather
        // than overwrite with zero-adjacent garbage or throw.
        var empty = new CK_FUNCTION_LIST_3_2 { version = new CK_VERSION { Major = 3, Minor = 2 } };
        IntPtr v32Table = Alloc(Marshal.SizeOf<CK_FUNCTION_LIST_3_2>() + 64);
        WriteTable(v32Table, in empty);
        s_functionListPtr = baseTable;
        s_interfacePtr = BuildInterface(v32Table);
        s_getInterfaceRv = 0;

        var delegates = new Delegates(Resolver(new()
        {
            ["C_GetFunctionList"] = GetFunctionListStub,
            ["C_GetInterface"] = GetInterfaceStub,
        }));

        AssertAllZero(delegates, V30AdditionNames(), "C_GetInterface");
        AssertAllZero(delegates, V32AdditionNames());
    }

    [Fact]
    public void MissingGetFunctionList_ThrowsEntryPointNotFound()
        => Assert.Throws<EntryPointNotFoundException>(() => new Delegates(Resolver([])));

    [Fact]
    public void SlotName_Coverage_SanityCheck()
    {
        // Guards the test harness itself: the struct definitions must expose the expected
        // slot populations, or the reflection sweep would silently assert nothing.
        Assert.True(SlotNames<CK_FUNCTION_LIST>().Count() >= 60, "v2.40 table lost slots");
        Assert.True(V30AdditionNames().Count() >= 20, "v3.0 additions lost slots");
        Assert.Equal(12, V32AdditionNames().Count());
    }
}
