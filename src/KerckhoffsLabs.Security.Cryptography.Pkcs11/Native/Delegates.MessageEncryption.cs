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
    // ── Has* availability properties for optional v3.0/v3.2 functions ─────────────

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageEncryptInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageEncryptInit => _fp.C_MessageEncryptInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncryptMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_EncryptMessage => _fp.C_EncryptMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncryptMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_EncryptMessageBegin => _fp.C_EncryptMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_EncryptMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_EncryptMessageNext => _fp.C_EncryptMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageEncryptFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageEncryptFinal => _fp.C_MessageEncryptFinal is not null;

    /// <summary>Wrapper for <c>C_MessageEncryptInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageEncryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageEncryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageEncryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageEncryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_EncryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext, byte[]? ciphertext, out NativeCULong ciphertextLen)
    {
        ciphertextLen = (NativeCULong)(ciphertext?.Length ?? 0);
        ThrowIfUnbound(_fp.C_EncryptMessage);
        // `fixed` yields a null pointer for ANY empty array or span, even a real (non-null) one --
        // that's fine for parameters where the caller never means "null" (associatedData,
        // plaintext: always real, possibly-empty data here), so a dummy byte's address stands in,
        // never dereferenced since the paired length is 0. ciphertext is the one parameter where
        // null is a deliberate signal (the length-probe call) distinct from a real, empty output
        // buffer, so it alone is allowed to reach the native call as a genuine null pointer.
        byte sentinel = 0;
        fixed (byte* adRaw = associatedData)
        fixed (byte* ptRaw = plaintext)
        fixed (byte* ctRaw = ciphertext)
        fixed (NativeCULong* ctLenPtr = &ciphertextLen)
        {
            byte* adPtr = associatedData.Length == 0 ? &sentinel : adRaw;
            byte* ptPtr = plaintext.Length == 0 ? &sentinel : ptRaw;
            byte* ctPtr = SentinelOrData(ciphertext, ctRaw, &sentinel);
            return _fp.C_EncryptMessage(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length, ptPtr, (NativeCULong)plaintext.Length, ctPtr, ctLenPtr);
        }
    }

    /// <summary>Wrapper for <c>C_EncryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> associatedData)
    {
        ThrowIfUnbound(_fp.C_EncryptMessageBegin);
        fixed (byte* adPtr = associatedData)
            return _fp.C_EncryptMessageBegin(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length);
    }

    /// <summary>Wrapper for <c>C_EncryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> plaintextPart, Span<byte> ciphertextPart, out NativeCULong ciphertextPartLen, NativeCULong flags)
    {
        ciphertextPartLen = (NativeCULong)ciphertextPart.Length;
        ThrowIfUnbound(_fp.C_EncryptMessageNext);
        fixed (byte* ptPtr = plaintextPart)
        fixed (byte* ctPtr = ciphertextPart)
        fixed (NativeCULong* ctLenPtr = &ciphertextPartLen)
            return _fp.C_EncryptMessageNext(session, parameter, parameterLen, ptPtr, (NativeCULong)plaintextPart.Length, ctPtr, ctLenPtr, flags);
    }

    /// <summary>Wrapper for <c>C_MessageEncryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageEncryptFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageEncryptFinal);
        return _fp.C_MessageEncryptFinal(session);
    }
}
