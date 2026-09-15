// <auto-split-from Delegates.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

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
    /// <summary>Wrapper for <c>C_Initialize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Initialize(IntPtr pInitArgs)
    {
        ThrowIfUnbound(_fp.C_Initialize);
        return _fp.C_Initialize(pInitArgs);
    }

    /// <summary>Wrapper for <c>C_Finalize</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Finalize(IntPtr reserved)
    {
        ThrowIfUnbound(_fp.C_Finalize);
        return _fp.C_Finalize(reserved);
    }

    /// <summary>Wrapper for <c>C_GetInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetInfo(ref CK_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetInfo_Windows);
            CK_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetInfo_Windows(&win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetInfo);
        fixed (CK_INFO* p = &info) return _fp.C_GetInfo(p);
    }

    /// <summary>Wrapper for <c>C_GetFunctionList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetFunctionList(out IntPtr functionList)
    {
        ThrowIfUnbound(_fp.C_GetFunctionList);
        IntPtr local = IntPtr.Zero;
        NativeCULong rv = _fp.C_GetFunctionList(&local);
        functionList = local;
        return rv;
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_GetInterfaceList</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_GetInterfaceList => _fp.C_GetInterfaceList is not null;

    /// <summary>Wrapper for <c>C_GetInterfaceList</c> (PKCS#11 v3.0). Two-call idiom: pass <c>null</c> to get the count.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetInterfaceList(CK_INTERFACE[]? interfaces, ref NativeCULong count)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetInterfaceList_Windows);
            if (interfaces is null)
            {
                fixed (NativeCULong* c = &count)
                    return _fp.C_GetInterfaceList_Windows(null, c);
            }

            var winList = new CK_INTERFACE_Windows[interfaces.Length];
            NativeCULong winRv;
            fixed (CK_INTERFACE_Windows* list = winList)
            fixed (NativeCULong* c = &count)
                winRv = _fp.C_GetInterfaceList_Windows(list, c);
            if (winRv.ToCKR() == CKR.CKR_OK)
                for (int i = 0; i < interfaces.Length; i++)
                    interfaces[i] = winList[i].ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetInterfaceList);
        fixed (CK_INTERFACE* list = interfaces)
        fixed (NativeCULong* c = &count)
            return _fp.C_GetInterfaceList(list, c);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_GetInterface</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_GetInterface => _fp.C_GetInterface is not null;

    /// <summary>
    /// Wrapper for <c>C_GetInterface</c> (PKCS#11 v3.0). Requests the interface named
    /// <paramref name="interfaceName"/> (a NUL-terminated UTF-8 string, or <c>null</c> for the module's
    /// default interface) and reads back the token-owned <see cref="CK_INTERFACE"/> descriptor (the
    /// version argument is always passed as <c>NULL</c> — any version). The returned struct is read via
    /// <see cref="UnmanagedMemory.Read{T}"/>, which applies the correct platform layout, so no Pack=1
    /// sibling wrapper is needed (unlike <c>C_GetInterfaceList</c>, the token owns the memory and we
    /// only read it).
    /// </summary>
    public unsafe NativeCULong C_GetInterface(ReadOnlySpan<byte> interfaceName, NativeCULong flags, out CK_INTERFACE iface)
    {
        iface = default;
        ThrowIfUnbound(_fp.C_GetInterface);

        IntPtr interfacePtr;
        NativeCULong rv;
        fixed (byte* namePtr = interfaceName)
            rv = _fp.C_GetInterface(namePtr, IntPtr.Zero, &interfacePtr, flags);

        if (rv.ToCKR() == CKR.CKR_OK && interfacePtr != IntPtr.Zero)
            iface = UnmanagedMemory.Read<CK_INTERFACE>(interfacePtr);
        return rv;
    }
}
