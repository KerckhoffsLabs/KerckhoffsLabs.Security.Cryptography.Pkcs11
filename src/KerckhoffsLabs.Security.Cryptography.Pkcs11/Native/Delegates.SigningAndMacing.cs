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
    /// <summary>Wrapper for <c>C_SignInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_SignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_SignInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_SignInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_SignInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_SignInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Sign</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Sign(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_Sign);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_Sign(session, dataPtr, (NativeCULong)data.Length, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ThrowIfUnbound(_fp.C_SignUpdate);
        fixed (byte* partPtr = part)
            return _fp.C_SignUpdate(session, partPtr, (NativeCULong)part.Length);
    }

    /// <summary>Wrapper for <c>C_SignFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignFinal(NativeCULong session, Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignFinal);
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_SignFinal(session, sigPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_SignRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_SignRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_SignRecoverInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_SignRecoverInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_SignRecoverInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_SignRecoverInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_SignRecover</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> signature, out NativeCULong signatureLen)
    {
        signatureLen = (NativeCULong)signature.Length;
        ThrowIfUnbound(_fp.C_SignRecover);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
        fixed (NativeCULong* lenPtr = &signatureLen)
            return _fp.C_SignRecover(session, dataPtr, (NativeCULong)data.Length, sigPtr, lenPtr);
    }
}
