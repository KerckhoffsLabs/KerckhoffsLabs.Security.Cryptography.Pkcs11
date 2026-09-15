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
    /// <summary>Wrapper for <c>C_GetSlotList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
    {
        ThrowIfUnbound(_fp.C_GetSlotList);
        fixed (NativeCULong* slotPtr = slotList)
        fixed (NativeCULong* countPtr = &count)
            return _fp.C_GetSlotList((byte)(tokenPresent ? 1 : 0), slotPtr, countPtr);
    }

    /// <summary>Wrapper for <c>C_GetSlotInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetSlotInfo_Windows);
            CK_SLOT_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetSlotInfo_Windows(slotId, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetSlotInfo);
        fixed (CK_SLOT_INFO* p = &info) return _fp.C_GetSlotInfo(slotId, p);
    }

    /// <summary>Wrapper for <c>C_GetTokenInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetTokenInfo_Windows);
            CK_TOKEN_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetTokenInfo_Windows(slotId, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetTokenInfo);
        fixed (CK_TOKEN_INFO* p = &info) return _fp.C_GetTokenInfo(slotId, p);
    }

    /// <summary>Wrapper for <c>C_GetMechanismList</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_GetMechanismList(NativeCULong slotId, NativeCULong[]? mechanismList, ref NativeCULong count)
    {
        ThrowIfUnbound(_fp.C_GetMechanismList);
        fixed (NativeCULong* mechPtr = mechanismList)
        fixed (NativeCULong* countPtr = &count)
            return _fp.C_GetMechanismList(slotId, mechPtr, countPtr);
    }

    /// <summary>Wrapper for <c>C_GetMechanismInfo</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_GetMechanismInfo(NativeCULong slotId, NativeCULong type, ref CK_MECHANISM_INFO info)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_GetMechanismInfo_Windows);
            CK_MECHANISM_INFO_Windows win = default;
            NativeCULong winRv = _fp.C_GetMechanismInfo_Windows(slotId, type, &win);
            info = win.ToUnified();
            return winRv;
        }

        ThrowIfUnbound(_fp.C_GetMechanismInfo);
        fixed (CK_MECHANISM_INFO* p = &info) return _fp.C_GetMechanismInfo(slotId, type, p);
    }

    /// <summary>Wrapper for <c>C_InitToken</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label)
    {
        ThrowIfUnbound(_fp.C_InitToken);
        fixed (byte* pinPtr = pin)
        fixed (byte* labelPtr = label)
            return _fp.C_InitToken(slotId, pinPtr, (NativeCULong)pin.Length, labelPtr);
    }

    /// <summary>Wrapper for <c>C_WaitForSlotEvent</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved)
    {
        ThrowIfUnbound(_fp.C_WaitForSlotEvent);
        fixed (NativeCULong* slotPtr = &slot)
            return _fp.C_WaitForSlotEvent(flags, slotPtr, reserved);
    }
}
