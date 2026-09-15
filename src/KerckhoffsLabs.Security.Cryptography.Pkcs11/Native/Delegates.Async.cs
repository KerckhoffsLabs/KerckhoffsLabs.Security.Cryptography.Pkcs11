// <auto-split-from Delegates.cs>

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
    /// <summary>Wrapper for <c>C_AsyncComplete</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_AsyncComplete(NativeCULong session, ReadOnlySpan<byte> functionName, ref CK_ASYNC_DATA result)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_AsyncComplete_Windows);
            CK_ASYNC_DATA_Windows win = default;
            NativeCULong winRv;
            fixed (byte* fnPtr = functionName)
                winRv = _fp.C_AsyncComplete_Windows(session, fnPtr, &win);
            result = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_AsyncComplete);
        fixed (byte* fnPtr = functionName)
        fixed (CK_ASYNC_DATA* rPtr = &result)
            return _fp.C_AsyncComplete(session, fnPtr, rPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncComplete</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncComplete => _fp.C_AsyncComplete is not null;

    /// <summary>Wrapper for <c>C_AsyncGetID</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_AsyncGetID(NativeCULong session, ReadOnlySpan<byte> functionName, ref NativeCULong id)
    {
        ThrowIfUnbound(_fp.C_AsyncGetID);
        fixed (byte* fnPtr = functionName)
        fixed (NativeCULong* idPtr = &id)
            return _fp.C_AsyncGetID(session, fnPtr, idPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncGetID</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncGetID => _fp.C_AsyncGetID is not null;

    /// <summary>Wrapper for <c>C_AsyncJoin</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_AsyncJoin(NativeCULong session, ReadOnlySpan<byte> functionName, NativeCULong id, ReadOnlySpan<byte> data)
    {
        ThrowIfUnbound(_fp.C_AsyncJoin);
        fixed (byte* fnPtr = functionName)
        fixed (byte* dataPtr = data)
            return _fp.C_AsyncJoin(session, fnPtr, id, dataPtr, (NativeCULong)data.Length);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_AsyncJoin</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_AsyncJoin => _fp.C_AsyncJoin is not null;
}
