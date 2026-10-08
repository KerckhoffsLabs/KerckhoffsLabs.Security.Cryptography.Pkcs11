using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

// Reading a module's function table: once per module handle, before any call goes through it.
internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>Native Cryptoki bootstrap symbol name, used for export lookup and error context.</summary>
    private const string GetFunctionListSymbol = "C_GetFunctionList";

    /// <summary>The interface versions this library binds, newest first (PKCS#11 v3.0 §5.4.4).</summary>
    private static readonly CK_VERSION[] KnownInterfaceVersions =
    [
        new() { Major = 3, Minor = 2 },
        new() { Major = 3, Minor = 1 },
        new() { Major = 3, Minor = 0 },
    ];

    /// <summary>
    /// Reads the function table of the module loaded at <paramref name="libraryHandle"/>, or of the host
    /// executable when it is <see cref="IntPtr.Zero"/> (a statically linked module).
    /// </summary>
    /// <remarks>
    /// A statically linked module's exports live in the entry-point module, which
    /// <see cref="NativeLibrary.GetMainProgramHandle"/> resolves against on CoreCLR and Native AOT alike, so
    /// the static path is the ordinary load sequence over a different handle.
    /// </remarks>
    internal static CryptokiTable LoadTable(IntPtr libraryHandle)
        => LoadTable(ResolverFor(libraryHandle != IntPtr.Zero ? libraryHandle : NativeLibrary.GetMainProgramHandle()));

    /// <summary>
    /// Reads a module's function table through an export resolver: the module's newest interface table
    /// this library knows, from <c>C_GetInterface</c>; failing that, the v2.40 table from
    /// <c>C_GetFunctionList</c>. Every slot, base and v3.x alike, comes from the one table chosen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is also the test seam: a test hands in a resolver returning managed
    /// <c>[UnmanagedCallersOnly]</c> functions and synthetic tables, so the real negotiation and binding
    /// run without a native module.
    /// </para>
    /// <para>
    /// The v3.x functions come only from an interface table (PKCS#11 v3.0 §5.4), never from per-symbol
    /// exports: <see cref="NativeLibrary.TryGetExport"/> searches the module's dependencies too (and the
    /// global scope for a statically linked module), so it could bind another module's function. A module
    /// without a usable interface table has the v2.40 surface only; its v3.x calls report
    /// <c>CKR_FUNCTION_NOT_SUPPORTED</c>.
    /// </para>
    /// </remarks>
    /// <param name="resolveExport">Maps an export name to its address, or <see cref="IntPtr.Zero"/> when absent.</param>
    internal static CryptokiTable LoadTable(Func<string, IntPtr> resolveExport)
        => TryReadInterfaceTable(resolveExport, out CryptokiTable table) ? table : ReadFunctionList(resolveExport);

    /// <summary>Export resolver over an OS library handle (returns Zero for missing exports).</summary>
    private static Func<string, IntPtr> ResolverFor(IntPtr libraryHandle)
        => name => NativeLibrary.TryGetExport(libraryHandle, name, out IntPtr address) ? address : IntPtr.Zero;

    /// <summary>
    /// Negotiates the module's interface through <c>C_GetInterface</c> and reads every slot from the table
    /// it hands back. Returns <see langword="false"/>, reading nothing, when the module has no
    /// <c>C_GetInterface</c> or offers no v3.x table this library can read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each known version is requested by name and version, newest first, and a table is accepted only if
    /// its own <c>CK_VERSION</c> header is the version asked for: a module that ignores the request and
    /// hands back another table is not believed. Only when every exact request fails is the default
    /// interface (<c>C_GetInterface(NULL, NULL)</c>) taken, and read strictly by its header: {3,2} as a
    /// v3.2 table; {3,0}, {3,1} and any later 3.x as a v3.0 table, which they all extend; any other
    /// major version not at all.
    /// </para>
    /// <para>
    /// The tables of every version extend one another (they are generated from one <c>pkcs11f.h</c>), so
    /// the base v2.40 slots are read from the same table as the v3.x additions, and the slot count read
    /// never exceeds what the verified version defines.
    /// </para>
    /// </remarks>
    private static unsafe bool TryReadInterfaceTable(Func<string, IntPtr> resolveExport, out CryptokiTable table)
    {
        table = default;
        IntPtr getInterfaceAddress = resolveExport("C_GetInterface");
        if (getInterfaceAddress == IntPtr.Zero)
            return false;
        var getInterface = (delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong>)getInterfaceAddress;

        foreach (CK_VERSION wanted in KnownInterfaceVersions)
        {
            if (TryGetInterfaceTable(getInterface, wanted, out IntPtr list, out _))
            {
                table = CryptokiTable.Read(list, wanted.Minor == 2 ? CryptokiTable.V32SlotCount : CryptokiTable.V30SlotCount);
                return true;
            }
        }

        if (TryGetInterfaceTable(getInterface, null, out IntPtr defaultList, out CK_VERSION header) && header.Major == 3)
        {
            table = CryptokiTable.Read(defaultList, header.Minor == 2 ? CryptokiTable.V32SlotCount : CryptokiTable.V30SlotCount);
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
    private static unsafe bool TryGetInterfaceTable(
        delegate* unmanaged[Cdecl]<byte*, IntPtr, IntPtr*, NativeCULong, NativeCULong> getInterface,
        CK_VERSION? wanted, out IntPtr table, out CK_VERSION header)
    {
        table = IntPtr.Zero;
        header = default;

        CK_VERSION requested = wanted.GetValueOrDefault();
        IntPtr interfacePtr = IntPtr.Zero;
        NativeCULong rv;
        fixed (byte* name = "PKCS 11\0"u8)
        {
            rv = wanted.HasValue
                ? getInterface(name, (IntPtr)(&requested), &interfacePtr, new NativeCULong(0))
                : getInterface(null, IntPtr.Zero, &interfacePtr, new NativeCULong(0));
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

    /// <summary>Reads the v2.40 table <c>C_GetFunctionList</c> returns.</summary>
    /// <exception cref="EntryPointNotFoundException">The module exports no <c>C_GetFunctionList</c>.</exception>
    /// <exception cref="Pkcs11Exception"><c>C_GetFunctionList</c> failed.</exception>
    /// <exception cref="InvalidOperationException"><c>C_GetFunctionList</c> succeeded without returning a table.</exception>
    private static unsafe CryptokiTable ReadFunctionList(Func<string, IntPtr> resolveExport)
    {
        // Mirrors NativeLibrary.GetExport's contract: a missing bootstrap symbol is fatal.
        IntPtr getFunctionListAddress = resolveExport(GetFunctionListSymbol);
        if (getFunctionListAddress == IntPtr.Zero)
            throw new EntryPointNotFoundException(
                $"Unable to find an entry point named '{GetFunctionListSymbol}' in the PKCS#11 library.");
        var getFunctionList = (delegate* unmanaged[Cdecl]<IntPtr*, NativeCULong>)getFunctionListAddress;

        IntPtr functionList = IntPtr.Zero;
        CKR returnValue = getFunctionList(&functionList).ToCKR();
        Pkcs11Exception.ThrowIfError(returnValue, GetFunctionListSymbol);
        if (functionList == IntPtr.Zero)
            throw new InvalidOperationException(
                "C_GetFunctionList succeeded but returned a null function-list pointer.");

        return CryptokiTable.Read(functionList, CryptokiTable.V240SlotCount);
    }
}
