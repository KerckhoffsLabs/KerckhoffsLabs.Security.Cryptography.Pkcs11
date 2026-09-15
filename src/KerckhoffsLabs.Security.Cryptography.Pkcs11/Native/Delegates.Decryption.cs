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
    /// <summary>Wrapper for <c>C_DecryptInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_DecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_DecryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_DecryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_DecryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_DecryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Decrypt</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, Span<byte> data, out NativeCULong dataLen)
    {
        dataLen = (NativeCULong)data.Length;
        ThrowIfUnbound(_fp.C_Decrypt);
        fixed (byte* encDataPtr = encryptedData)
        fixed (byte* dataPtr = data)
        fixed (NativeCULong* lenPtr = &dataLen)
            return _fp.C_Decrypt(session, encDataPtr, (NativeCULong)encryptedData.Length, dataPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, Span<byte> part, out NativeCULong partLen)
    {
        partLen = (NativeCULong)part.Length;
        ThrowIfUnbound(_fp.C_DecryptUpdate);
        fixed (byte* encPartPtr = encryptedPart)
        fixed (byte* partPtr = part)
        fixed (NativeCULong* lenPtr = &partLen)
            return _fp.C_DecryptUpdate(session, encPartPtr, (NativeCULong)encryptedPart.Length, partPtr, lenPtr);
    }

    /// <summary>Wrapper for <c>C_DecryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_DecryptFinal(NativeCULong session, Span<byte> lastPart, out NativeCULong lastPartLen)
    {
        lastPartLen = (NativeCULong)lastPart.Length;
        ThrowIfUnbound(_fp.C_DecryptFinal);
        fixed (byte* partPtr = lastPart)
        fixed (NativeCULong* lenPtr = &lastPartLen)
            return _fp.C_DecryptFinal(session, partPtr, lenPtr);
    }
}
