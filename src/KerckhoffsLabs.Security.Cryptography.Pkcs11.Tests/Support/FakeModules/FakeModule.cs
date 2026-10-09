using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

/// <summary>
/// A PKCS#11 module made of managed code, loaded through the library's real loader. A test derives
/// from it and overrides the <c>C_*</c> functions its scenario needs; every call then crosses the
/// same function table, wrappers, pinning, <c>CK_ULONG</c> widths and Windows struct packing as a
/// native module would.
/// </summary>
/// <remarks>
/// <para>
/// The module exports <c>C_GetFunctionList</c> with a v2.40 table. One that implements a v3.x function also
/// exports <c>C_GetInterface</c>, which hands out a v3.2 table, so the loader binds it as a v3.2 module. A
/// function the subclass does not override leaves its slot NULL, exactly like a module that does not
/// implement it, so the library's own "function not supported" handling runs. <c>C_Initialize</c> and
/// <c>C_Finalize</c> are bound unless the module is built without them, and succeed unless overridden.
/// </para>
/// <para>
/// The table's functions are static <c>[UnmanagedCallersOnly]</c> thunks, so they find their instance
/// through a registry. Calls that carry a session or slot handle are routed by the instance id the
/// handle encodes (see <see cref="NewSessionHandle"/>), so a session finalized after its test ended
/// cannot reach a later test's module. Calls that carry no handle (<c>C_Initialize</c>,
/// <c>C_GetInfo</c>, ...) go to the one active module, which is why at most one may be alive at a
/// time and tests using it belong to the non-parallel <see cref="FakeModuleCollection"/>.
/// </para>
/// <para>
/// A thunk never lets an exception unwind into native code (that would end the process): it records
/// the first one, returns <c>CKR_GENERAL_ERROR</c>, and <see cref="Dispose"/> rethrows it.
/// </para>
/// </remarks>
internal abstract unsafe partial class FakeModule : IDisposable
{
    private const int InstanceShift = 24;
    private const uint InstanceMask = 0x7F;

    private static readonly Lock s_lock = new();
    private static readonly Dictionary<uint, FakeModule> s_modules = [];
    private static FakeModule? s_active;
    private static uint s_lastId;

    private readonly uint _id;
    private readonly bool _bindsLifecycle;
    private readonly ConcurrentDictionary<string, int> _calls = new(StringComparer.Ordinal);
    private IntPtr _functionList;
    private IntPtr _interfaceTable;
    private IntPtr _interfaceName;
    private IntPtr _interface;
    private IntPtr _answer;
    private ExceptionDispatchInfo? _fault;
    private ulong _nextHandle;
    private bool _disposed;

    protected FakeModule()
        : this(bindsLifecycle: true)
    {
    }

    /// <param name="bindsLifecycle">
    /// <see langword="false"/> leaves <c>C_Initialize</c> and <c>C_Finalize</c> out of the table too, for a
    /// module that lacks even those.
    /// </param>
    protected FakeModule(bool bindsLifecycle)
    {
        _bindsLifecycle = bindsLifecycle;
        _id = Register(this);
        BuildFunctionLists();
    }

    /// <summary>How many times each <c>C_*</c> function was called, by name.</summary>
    public IReadOnlyDictionary<string, int> Calls => _calls;

    /// <summary>The number of calls to <paramref name="function"/>, zero if none.</summary>
    public int CallCount(string function) => _calls.GetValueOrDefault(function);

    /// <summary>Loads this module through the real loader and initializes it, as <c>Pkcs11Library.Load</c> would.</summary>
    public Pkcs11Library Load(ILoggerFactory? loggerFactory = null) => new(ResolveExport, loggerFactory);

    /// <summary>Loads this module and initializes it with <paramref name="options"/>, as
    /// <c>Pkcs11Library.Load(path, options)</c> would.</summary>
    public Pkcs11Library Load(Pkcs11LibraryOptions options) => new(ResolveExport, options.LoggerFactory, options);

    /// <summary>Binds this module through the real loader without initializing it.</summary>
    public LowLevelPkcs11Library LoadLowLevel() => new(ResolveExport);

    /// <summary>
    /// A fresh handle that carries this module's instance id, for the session and slot handles the
    /// module hands out, so calls on them reach this instance even from another test's lifetime.
    /// </summary>
    protected NativeCULong NewSessionHandle()
        => (NativeCULong)((ulong)_id << InstanceShift | Interlocked.Increment(ref _nextHandle));

    public void Dispose()
    {
        if (Release())
            _fault?.Throw();
    }

    /// <summary>
    /// Whether a successful <c>C_Finalize</c> releases this module, for a module a test reaches only through
    /// the <see cref="Pkcs11Library"/> from <see cref="Load(ILoggerFactory?)"/>: disposing that library finalizes the module,
    /// and so releases it. A fault such a module records is lost with it, so this suits a module that models
    /// a token, not one that injects faults.
    /// </summary>
    protected virtual bool ReleasedByFinalize => false;

    /// <summary>Unregisters the module and frees its tables, once; <see langword="false"/> if already done.</summary>
    private bool Release()
    {
        if (_disposed)
            return false;
        _disposed = true;

        Disposing();

        Unregister(this);

        Marshal.FreeHGlobal(_functionList);
        Marshal.FreeHGlobal(_interfaceTable);
        Marshal.FreeHGlobal(_interfaceName);
        Marshal.FreeHGlobal(_interface);
        Marshal.FreeHGlobal(_answer);
        _functionList = _interfaceTable = _interfaceName = _interface = _answer = IntPtr.Zero;
        return true;
    }

    /// <summary>Releases what a derived module holds before the module unregisters and frees its tables.</summary>
    protected virtual void Disposing()
    {
    }

    // --- registry --------------------------------------------------------------------------------
    // The registry is static state shared by every instance, so only these two static methods write it.

    /// <summary>Makes <paramref name="module"/> the active module and returns its instance id.</summary>
    private static uint Register(FakeModule module)
    {
        lock (s_lock)
        {
            if (s_active is not null)
                throw new InvalidOperationException(
                    $"{s_active.GetType().Name} is still active; dispose it first. Tests using a FakeModule belong to [Collection(FakeModuleCollection.Name)].");

            s_lastId = s_lastId % InstanceMask + 1;
            s_modules[s_lastId] = module;
            s_active = module;
            return s_lastId;
        }
    }

    private static void Unregister(FakeModule module)
    {
        lock (s_lock)
        {
            s_modules.Remove(module._id);
            if (ReferenceEquals(s_active, module))
                s_active = null;
        }
    }

    // --- export resolution and routing -------------------------------------------------------

    private IntPtr ResolveExport(string name) => name switch
    {
        "C_GetFunctionList" => (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)&GetFunctionList,
        "C_GetInterface" when _interface != IntPtr.Zero => GetInterfaceAddress,
        _ => IntPtr.Zero,
    };

    private static IntPtr GetInterfaceAddress => (IntPtr)(delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)&GetInterface;

    // The loader asks through the export, and gets the one interface this module has whatever name and
    // version it asks for: the v3.2 table, the version the loader asks for first.
    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static NativeCULong GetInterface(byte* pInterfaceName, IntPtr pVersion, IntPtr* ppInterface, NativeCULong flags)
    {
        FakeModule? m = Active("C_GetInterface");
        if (m is null || m._interface == IntPtr.Zero)
            return Rv(CKR.CKR_GENERAL_ERROR);
        *ppInterface = m._interface;
        return Rv(CKR.CKR_OK);
    }

    private static IntPtr TableGetInterfaceAddress => (IntPtr)(delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)&TableGetInterface;

    /// <summary>
    /// Answers <c>C_GetInterface</c> called through the module's v3.2 table, as <c>Pkcs11Library.GetInterface</c>
    /// calls it. <paramref name="interfaceName"/> is the name as passed, terminator included, or
    /// <see langword="null"/>; <paramref name="iface"/> arrives holding this module's own interface. A module
    /// that overrides this exports <c>C_GetInterface</c> even if it implements no other v3.x function.
    /// </summary>
    protected virtual CKR C_GetInterface(byte[]? interfaceName, NativeCULong flags, ref CK_INTERFACE iface) => CKR.CKR_OK;

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static NativeCULong TableGetInterface(byte* pInterfaceName, IntPtr pVersion, IntPtr* ppInterface, NativeCULong flags)
    {
        if (Active(nameof(C_GetInterface)) is not { _interface: not 0 } m) return Rv(CKR.CKR_GENERAL_ERROR);
        try
        {
            byte[]? name = pInterfaceName is null ? null : [.. MemoryMarshal.CreateReadOnlySpanFromNullTerminated(pInterfaceName), 0];
            CK_INTERFACE answer = ReadStruct<CK_INTERFACE>((void*)m._interface);
            CKR rv = m.C_GetInterface(name, flags, ref answer);
            if (rv == CKR.CKR_OK)
            {
                UnmanagedMemory.Write(m._answer, answer);
                *ppInterface = m._answer;
            }
            return Rv(rv);
        }
        catch (Exception ex) when (m.RecordFault(ex)) { return Rv(CKR.CKR_GENERAL_ERROR); }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(System.Runtime.CompilerServices.CallConvCdecl)])]
    private static NativeCULong GetFunctionList(IntPtr* ppFunctionList)
    {
        FakeModule? m = Active("C_GetFunctionList");
        if (m is null)
            return Rv(CKR.CKR_GENERAL_ERROR);
        *ppFunctionList = m._functionList;
        return Rv(CKR.CKR_OK);
    }

    /// <summary>The module a handle-less call belongs to: the active one.</summary>
    private static FakeModule? Active(string function)
    {
        FakeModule? m;
        lock (s_lock)
            m = s_active;
        m?.Count(function);
        return m;
    }

    /// <summary>
    /// The module a handle-carrying call belongs to: the one whose instance id the handle encodes, or
    /// the active module for a handle that encodes none (a test that hands out plain small numbers).
    /// </summary>
    private static FakeModule? Owner(NativeCULong handle, string function)
    {
        // Any CK_ULONG is a legal handle, so the narrowing must not trap on the high bits it discards.
        uint id = unchecked((uint)((ulong)handle >> InstanceShift)) & InstanceMask;
        FakeModule? m;
        lock (s_lock)
            m = id != 0 && s_modules.TryGetValue(id, out FakeModule? owner) ? owner : id == 0 ? s_active : null;
        m?.Count(function);
        return m;
    }

    private void Count(string function) => _calls.AddOrUpdate(function, 1, static (_, n) => n + 1);

    /// <summary>
    /// The exception filter on every thunk's catch: records the first fault for <see cref="Dispose"/> to
    /// rethrow and returns <see langword="true"/>, so the thunk returns <c>CKR_GENERAL_ERROR</c>. Catching
    /// everything is deliberate (an exception unwinding out of an <c>[UnmanagedCallersOnly]</c> method
    /// ends the process), and running as a filter captures the fault before the stack unwinds.
    /// </summary>
    private bool RecordFault(Exception ex)
    {
        Interlocked.CompareExchange(ref _fault, ExceptionDispatchInfo.Capture(ex), null);
        return true;
    }

    private static NativeCULong Rv(CKR rv) => (NativeCULong)(ulong)rv;

    // --- function table ------------------------------------------------------------------------

    /// <summary>Whether the concrete module overrides <paramref name="function"/>.</summary>
    private bool Overrides(string function)
        => GetType().GetMethod(function, BindingFlags.Instance | BindingFlags.NonPublic)!.DeclaringType != typeof(FakeModule);

    // The tables are in the layout a native module exports (Pack=1 on Windows).
    private void BuildFunctionLists()
    {
        var slots = new Dictionary<string, IntPtr>();
        BindFunctions(slots);

        HashSet<string> v240 = [.. NativeFunctionList.SlotNames.Take(CryptokiTable.V240SlotCount)];
        _functionList = NativeFunctionList.Allocate(2, 40, CryptokiTable.V240SlotCount,
            slots.Where(slot => v240.Contains(slot.Key)).ToDictionary());

        if (slots.Keys.All(v240.Contains) && !Overrides(nameof(C_GetInterface)))
            return;

        slots[nameof(CryptokiTable.C_GetInterface)] = TableGetInterfaceAddress;
        _interfaceTable = NativeFunctionList.Allocate(3, 2, CryptokiTable.V32SlotCount, slots);
        _interfaceName = Marshal.StringToHGlobalAnsi("PKCS 11");
        _interface = Marshal.AllocHGlobal(UnmanagedMemory.SizeOf<CK_INTERFACE>());
        _answer = Marshal.AllocHGlobal(UnmanagedMemory.SizeOf<CK_INTERFACE>());
        UnmanagedMemory.Write(_interface, new CK_INTERFACE { InterfaceName = _interfaceName, FunctionList = _interfaceTable, Flags = (NativeCULong)0 });
    }

    // --- marshalling helpers for the thunks --------------------------------------------------

    private static ReadOnlySpan<byte> In(byte* p, NativeCULong length)
        => p is null ? default : new ReadOnlySpan<byte>(p, checked((int)(ulong)length));

    private static T ReadStruct<T>(void* p) where T : unmanaged => UnmanagedMemory.Read<T>((IntPtr)p);

    private static void WriteStruct<T>(void* p, in T value) where T : unmanaged => UnmanagedMemory.Write((IntPtr)p, in value);

    private static CK_ATTRIBUTE[] ReadTemplate(void* p, NativeCULong count)
    {
        int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        var template = new CK_ATTRIBUTE[checked((int)(ulong)count)];
        for (int i = 0; i < template.Length; i++)
            template[i] = UnmanagedMemory.Read<CK_ATTRIBUTE>((IntPtr)((byte*)p + i * stride));
        return template;
    }

    private static void WriteTemplate(void* p, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        int stride = UnmanagedMemory.SizeOf<CK_ATTRIBUTE>();
        for (int i = 0; i < template.Length; i++)
            UnmanagedMemory.Write((IntPtr)((byte*)p + i * stride), in template[i]);
    }

    /// <summary>
    /// Answers one attribute of a <c>C_GetAttributeValue</c> template the way a module does: the length
    /// alone when the caller passed no buffer, the value when it fits, <c>CKR_BUFFER_TOO_SMALL</c>
    /// otherwise.
    /// </summary>
    protected static CKR AnswerAttribute(ref CK_ATTRIBUTE attribute, ReadOnlySpan<byte> value)
    {
        if (attribute.value == IntPtr.Zero)
        {
            attribute.valueLen = (NativeCULong)(ulong)value.Length;
            return CKR.CKR_OK;
        }
        if ((ulong)attribute.valueLen < (ulong)value.Length)
        {
            attribute.valueLen = NativeCULong.MaxValue;
            return CKR.CKR_BUFFER_TOO_SMALL;
        }
        value.CopyTo(new Span<byte>((void*)attribute.value, value.Length));
        attribute.valueLen = (NativeCULong)(ulong)value.Length;
        return CKR.CKR_OK;
    }
}

/// <summary>
/// An output buffer a module function receives: <see cref="IsNull"/> when the caller passed a NULL
/// pointer (a length query in the two-call convention), otherwise <see cref="Span"/> covers the
/// capacity the caller declared.
/// </summary>
internal readonly unsafe ref struct NativeBuffer<T> where T : unmanaged
{
    internal NativeBuffer(T* pointer, NativeCULong capacity)
    {
        IsNull = pointer is null;
        Span = IsNull ? default : new Span<T>(pointer, checked((int)(ulong)capacity));
    }

    public bool IsNull { get; }

    public Span<T> Span { get; }
}

/// <summary>Tests that use a <see cref="FakeModule"/>: at most one module is active at a time.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class FakeModuleCollection
{
    public const string Name = "FakeModule";
}
