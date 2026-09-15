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
    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageDecryptInit</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageDecryptInit => _fp.C_MessageDecryptInit is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecryptMessage</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_DecryptMessage => _fp.C_DecryptMessage is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecryptMessageBegin</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_DecryptMessageBegin => _fp.C_DecryptMessageBegin is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_DecryptMessageNext</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_DecryptMessageNext => _fp.C_DecryptMessageNext is not null;

    /// <summary>Returns <see langword="true"/> if the loaded library exported <c>C_MessageDecryptFinal</c> (PKCS#11 v3.0+).</summary>
    internal unsafe bool HasC_MessageDecryptFinal => _fp.C_MessageDecryptFinal is not null;

    /// <summary>Wrapper for <c>C_MessageDecryptInit</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_MessageDecryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_MessageDecryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_MessageDecryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_MessageDecryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_DecryptMessage</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, byte[]? plaintext, out NativeCULong plaintextLen)
    {
        plaintextLen = (NativeCULong)(plaintext?.Length ?? 0);
        ThrowIfUnbound(_fp.C_DecryptMessage);
        // See the identical comment in C_EncryptMessage: `fixed` yields a null pointer for any
        // empty array/span, real or not, so a dummy byte's address stands in for associatedData
        // and ciphertext (always real, possibly-empty data here) -- never dereferenced since the
        // paired length is 0. plaintext alone may be a genuine null (the length-probe signal),
        // which must reach the native call unchanged.
        byte sentinel = 0;
        fixed (byte* adRaw = associatedData)
        fixed (byte* ctRaw = ciphertext)
        fixed (byte* ptRaw = plaintext)
        fixed (NativeCULong* ptLenPtr = &plaintextLen)
        {
            byte* adPtr = associatedData.Length == 0 ? &sentinel : adRaw;
            byte* ctPtr = ciphertext.Length == 0 ? &sentinel : ctRaw;
            byte* ptPtr = SentinelOrData(plaintext, ptRaw, &sentinel);
            return _fp.C_DecryptMessage(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length, ctPtr, (NativeCULong)ciphertext.Length, ptPtr, ptLenPtr);
        }
    }

    /// <summary>Wrapper for <c>C_DecryptMessageBegin</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> associatedData)
    {
        ThrowIfUnbound(_fp.C_DecryptMessageBegin);
        fixed (byte* adPtr = associatedData)
            return _fp.C_DecryptMessageBegin(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length);
    }

    /// <summary>Wrapper for <c>C_DecryptMessageNext</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen,
        ReadOnlySpan<byte> ciphertextPart, Span<byte> plaintextPart, out NativeCULong plaintextPartLen, NativeCULong flags)
    {
        plaintextPartLen = (NativeCULong)plaintextPart.Length;
        ThrowIfUnbound(_fp.C_DecryptMessageNext);
        fixed (byte* ctPtr = ciphertextPart)
        fixed (byte* ptPtr = plaintextPart)
        fixed (NativeCULong* ptLenPtr = &plaintextPartLen)
            return _fp.C_DecryptMessageNext(session, parameter, parameterLen, ctPtr, (NativeCULong)ciphertextPart.Length, ptPtr, ptLenPtr, flags);
    }

    /// <summary>Wrapper for <c>C_MessageDecryptFinal</c> (PKCS#11 v3.0). Throws if the fptr is null.</summary>
    public unsafe NativeCULong C_MessageDecryptFinal(NativeCULong session)
    {
        ThrowIfUnbound(_fp.C_MessageDecryptFinal);
        return _fp.C_MessageDecryptFinal(session);
    }
}
