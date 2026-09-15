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
    /// <summary>Wrapper for <c>C_VerifyInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_VerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_VerifyInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_VerifyInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_VerifyInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_VerifyInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Verify</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_Verify);
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return _fp.C_Verify(session, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ThrowIfUnbound(_fp.C_VerifyUpdate);
        fixed (byte* partPtr = part)
            return _fp.C_VerifyUpdate(session, partPtr, (NativeCULong)part.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature)
    {
        ThrowIfUnbound(_fp.C_VerifyFinal);
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifyFinal(session, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifyRecoverInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_VerifyRecoverInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_VerifyRecoverInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_VerifyRecoverInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_VerifyRecoverInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_VerifyRecoverInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_VerifyRecover</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, Span<byte> data, out NativeCULong dataLen)
    {
        dataLen = (NativeCULong)data.Length;
        ThrowIfUnbound(_fp.C_VerifyRecover);
        fixed (byte* sigPtr = signature)
        fixed (byte* dataPtr = data)
        fixed (NativeCULong* lenPtr = &dataLen)
            return _fp.C_VerifyRecover(session, sigPtr, (NativeCULong)signature.Length, dataPtr, lenPtr);
    }

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignatureInit</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignatureInit => _fp.C_VerifySignatureInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignature</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignature => _fp.C_VerifySignature is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignatureUpdate</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignatureUpdate => _fp.C_VerifySignatureUpdate is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_VerifySignatureFinal</c> (PKCS#11 v3.2+).</summary>
    internal unsafe bool HasC_VerifySignatureFinal => _fp.C_VerifySignatureFinal is not null;

    /// <summary>Wrapper for <c>C_VerifySignatureInit</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_VerifySignatureInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_VerifySignatureInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            fixed (byte* sigPtr = signature)
                return _fp.C_VerifySignatureInit_Windows(session, &winMech, key, sigPtr, (NativeCULong)signature.Length);
        }

        ThrowIfUnbound(_fp.C_VerifySignatureInit);
        fixed (CK_MECHANISM* m = &mechanism)
        fixed (byte* sigPtr = signature)
            return _fp.C_VerifySignatureInit(session, m, key, sigPtr, (NativeCULong)signature.Length);
    }

    /// <summary>Wrapper for <c>C_VerifySignature</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data)
    {
        ThrowIfUnbound(_fp.C_VerifySignature);
        fixed (byte* dataPtr = data)
            return _fp.C_VerifySignature(session, dataPtr, (NativeCULong)data.Length);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureUpdate</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part)
    {
        ThrowIfUnbound(_fp.C_VerifySignatureUpdate);
        fixed (byte* partPtr = part)
            return _fp.C_VerifySignatureUpdate(session, partPtr, (NativeCULong)part.Length);
    }

    /// <summary>Wrapper for <c>C_VerifySignatureFinal</c> (PKCS#11 v3.2). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_VerifySignatureFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_VerifySignatureFinal);
        return _fp.C_VerifySignatureFinal(session);
    }
}
