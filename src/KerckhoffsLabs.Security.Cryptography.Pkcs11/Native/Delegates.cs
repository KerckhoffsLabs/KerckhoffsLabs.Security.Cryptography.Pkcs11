using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// Holds delegates for all PKCS#11 functions
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type IS the cryptoki dispatch boundary, and every unsafe region in it is one of " +
    "exactly three things C# permits nowhere else: invoking an unmanaged function pointer, pinning a managed " +
    "buffer for the duration of a native call, and taking the address of a blittable struct to pass as a " +
    "CK_*_PTR. There is no version of this file that satisfies the rule and still dispatches to a PKCS#11 " +
    "module. Suppressed at the type rather than per member so the rule keeps its value everywhere else: an " +
    "unsafe block appearing outside this boundary is still reported, and that is the case worth reviewing. " +
    "The safety argument does not rest on the suppression — every pointer is either pinned by a fixed " +
    "statement scoped to the call, or the address of a local, and every function pointer is null-checked by " +
    "ThrowIfUnbound before invocation. The dispatch table's binding is covered hermetically by " +
    "DelegatesLoaderTests, and the wrappers themselves by the full suite against SoftHSM2 and opencryptoki.")]
internal partial class Delegates
{

    /// <summary>The module's function table, copied once by the loader and only read after.</summary>
    internal CryptokiTable _fp;

    /// <summary>Native cryptoki bootstrap symbol name, used for export lookup and error context (S1192).</summary>
    private const string GetFunctionListSymbol = "C_GetFunctionList";

    /// <summary>
    /// Guards a wrapper against a function the loaded module never provided. The cryptoki name
    /// comes from the calling wrapper — each one is named after the function it dispatches to —
    /// so the error context cannot drift from the pointer being tested.
    /// </summary>
    /// <param name="function">Dispatch-table entry; <see langword="null"/> when unbound.</param>
    /// <param name="name">Supplied by the compiler. Do not pass explicitly.</param>
    private static unsafe void ThrowIfUnbound(void* function, [CallerMemberName] string name = "")
    {
        if (function is null)
            throw Pkcs11Exception.Create(CKR.CKR_FUNCTION_NOT_SUPPORTED, name);
    }

    /// <summary>
    /// Initializes a new instance of <see cref="Delegates"/>. Function pointers are
    /// acquired via <c>C_GetFunctionList</c> against the dynamically loaded library
    /// when <paramref name="libraryHandle"/> is non-zero, or against the host
    /// executable's own symbol table otherwise (a statically-linked module).
    /// </summary>
    /// <param name="libraryHandle">Handle to the dynamically loaded PKCS#11 library,
    /// or <see cref="IntPtr.Zero"/> for a statically-linked library.</param>
    internal Delegates(IntPtr libraryHandle)
        // A statically-linked module's exports live in the entry-point module, which
        // GetMainProgramHandle() resolves against on CoreCLR and Native AOT alike. That makes the
        // static path the ordinary load sequence over a different handle rather than a separate
        // bootstrap: same C_GetFunctionList entry, same best-effort v3.0/v3.2 binding, same
        // graceful degradation for exports a v2.40-only module does not provide.
        => Load(ResolverFor(libraryHandle != IntPtr.Zero
            ? libraryHandle
            : NativeLibrary.GetMainProgramHandle()));

    /// <summary>
    /// Initializes the dispatch table through an export resolver instead of an OS library
    /// handle. This is the hermetic-test seam: production goes through
    /// <see cref="Delegates(IntPtr)"/>, whose resolver wraps <see cref="NativeLibrary.TryGetExport"/>;
    /// tests supply a resolver returning managed <c>[UnmanagedCallersOnly]</c> stubs and
    /// synthetic function-list tables, so the real bootstrap / version-dispatch / slot-binding
    /// logic runs without any native module.
    /// </summary>
    /// <param name="resolveExport">Maps an export name to its address, or <see cref="IntPtr.Zero"/> when absent.</param>
    internal Delegates(Func<string, IntPtr> resolveExport) => Load(resolveExport);

    /// <summary>
    /// Load sequence: the module's newest interface table this library knows, from <c>C_GetInterface</c>;
    /// failing that, the v2.40 table from <c>C_GetFunctionList</c>. Every slot, base and v3.x alike, is
    /// bound from the one table chosen.
    /// </summary>
    /// <remarks>
    /// The v3.x functions come only from an interface table (PKCS#11 v3.0 §5.4), never from per-symbol
    /// exports: <see cref="NativeLibrary.TryGetExport"/> searches the module's dependencies too (and the
    /// global scope for a statically linked module), so it could bind another module's function. A module
    /// without a usable interface table has the v2.40 surface only; its v3.x calls report
    /// <c>CKR_FUNCTION_NOT_SUPPORTED</c>.
    /// </remarks>
    private void Load(Func<string, IntPtr> resolveExport)
    {
        if (!TryBindInterfaceTable(resolveExport))
            InitializeWithGetFunctionList(resolveExport);
    }

    /// <summary>Export resolver over an OS library handle (returns Zero for missing exports).</summary>
    private static Func<string, IntPtr> ResolverFor(IntPtr libraryHandle)
        => name => NativeLibrary.TryGetExport(libraryHandle, name, out IntPtr address) ? address : IntPtr.Zero;

    /// <summary>The interface versions this library binds, newest first (PKCS#11 v3.0 §5.4.4).</summary>
    private static readonly CK_VERSION[] KnownInterfaceVersions =
    [
        new() { Major = 3, Minor = 2 },
        new() { Major = 3, Minor = 1 },
        new() { Major = 3, Minor = 0 },
    ];

    /// <summary>
    /// Negotiates the module's interface through <c>C_GetInterface</c> and binds every slot from the table
    /// it hands back. Returns <see langword="false"/>, binding nothing, when the module has no
    /// <c>C_GetInterface</c> or offers no v3.x table this library can read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each known version is requested by name and version, newest first, and a table is accepted only if
    /// its own <c>CK_VERSION</c> header is the version asked for: a module that ignores the request and
    /// hands back another table is not believed. Only when every exact request fails is the default
    /// interface (<c>C_GetInterface(NULL, NULL)</c>) taken, and bound strictly by its header: {3,2} as a
    /// v3.2 table; {3,0}, {3,1} and any later 3.x as a v3.0 table, which they all extend; any other
    /// major version not at all.
    /// </para>
    /// <para>
    /// The tables of every version extend one another (they are generated from one <c>pkcs11f.h</c>), so
    /// the base v2.40 slots are read from the same table as the v3.x additions, and the slot count read
    /// never exceeds what the verified version defines.
    /// </para>
    /// </remarks>
    private bool TryBindInterfaceTable(Func<string, IntPtr> resolveExport)
    {
        if (!TryResolve(resolveExport, "C_GetInterface", out IntPtr getInterface))
            return false;
        unsafe { _fp.C_GetInterface = (delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)getInterface; }

        foreach (CK_VERSION wanted in KnownInterfaceVersions)
        {
            if (TryGetInterfaceTable(wanted, out IntPtr table, out _))
            {
                BindTable(table, isV32: wanted.Minor == 2);
                return true;
            }
        }

        if (TryGetInterfaceTable(null, out IntPtr defaultTable, out CK_VERSION header) && header.Major == 3)
        {
            BindTable(defaultTable, isV32: header.Minor == 2);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Calls <c>C_GetInterface</c> for the "PKCS 11" interface at <paramref name="wanted"/>, or for the
    /// default interface when it is <see langword="null"/>, and yields its function table and that table's
    /// version header. Fails on any error return, a NULL interface or table, and — for a requested version
    /// — a table whose header is not that version.
    /// </summary>
    private unsafe bool TryGetInterfaceTable(CK_VERSION? wanted, out IntPtr table, out CK_VERSION header)
    {
        table = IntPtr.Zero;
        header = default;

        CK_VERSION requested = wanted.GetValueOrDefault();
        IntPtr interfacePtr = IntPtr.Zero;
        NativeCULong rv;
        fixed (byte* name = "PKCS 11\0"u8)
        {
            rv = wanted.HasValue
                ? _fp.C_GetInterface(name, (IntPtr)(&requested), &interfacePtr, new NativeCULong(0))
                : _fp.C_GetInterface(null, IntPtr.Zero, &interfacePtr, new NativeCULong(0));
        }
        if (rv.ToCKR() != CKR.CKR_OK || interfacePtr == IntPtr.Zero)
            return false;

        CK_INTERFACE iface = UnmanagedMemory.Read<CK_INTERFACE>(interfacePtr);
        if (iface.FunctionList == IntPtr.Zero)
            return false;

        header = UnmanagedMemory.Read<CK_VERSION>(iface.FunctionList);
        if (wanted.HasValue && (header.Major != requested.Major || header.Minor != requested.Minor))
            return false;

        table = iface.FunctionList;
        return true;
    }

    /// <summary>
    /// Copies every slot from one v3.x interface table: the v3.2 count for a v3.2 table, the v3.0 count
    /// otherwise, never more than the verified version defines.
    /// </summary>
    private void BindTable(IntPtr table, bool isV32)
        => _fp = CryptokiTable.Read(table, isV32 ? CryptokiTable.V32SlotCount : CryptokiTable.V30SlotCount);
}
