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
    /// <summary>Wrapper for <c>C_EncryptInit</c>. Matches the prior delegate signature exactly.</summary>
    /// <remarks>On Windows the call is routed through the Pack=1 struct layout; the
    /// conversion to and from the unified structs happens here, so callers never see
    /// the packed types and never branch on the platform themselves.</remarks>
    public unsafe NativeCULong C_EncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        if (Pkcs11Marshal.IsWindows)
        {
            ThrowIfUnbound(_fp.C_EncryptInit_Windows);
            CK_MECHANISM_Windows winMech = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return _fp.C_EncryptInit_Windows(session, &winMech, key);
        }

        ThrowIfUnbound(_fp.C_EncryptInit);
        fixed (CK_MECHANISM* m = &mechanism) return _fp.C_EncryptInit(session, m, key);
    }

    /// <summary>Wrapper for <c>C_Encrypt</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, Span<byte> encryptedData, out NativeCULong encryptedDataLen)
    {
        encryptedDataLen = (NativeCULong)encryptedData.Length;
        ThrowIfUnbound(_fp.C_Encrypt);
        fixed (byte* dataPtr = data)
        fixed (byte* encDataPtr = encryptedData)
        fixed (NativeCULong* encLenPtr = &encryptedDataLen)
            return _fp.C_Encrypt(session, dataPtr, (NativeCULong)data.Length, encDataPtr, encLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptUpdate</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, Span<byte> encryptedPart,
        out NativeCULong encryptedPartLen)
    {
        encryptedPartLen = (NativeCULong)encryptedPart.Length;
        ThrowIfUnbound(_fp.C_EncryptUpdate);
        fixed (byte* partPtr = part)
        fixed (byte* encPartPtr = encryptedPart)
        fixed (NativeCULong* encLenPtr = &encryptedPartLen)
            return _fp.C_EncryptUpdate(session, partPtr, (NativeCULong)part.Length, encPartPtr, encLenPtr);
    }

    /// <summary>Wrapper for <c>C_EncryptFinal</c>. Matches the prior delegate signature exactly.</summary>
    public unsafe NativeCULong C_EncryptFinal(NativeCULong session, Span<byte> lastEncryptedPart, out NativeCULong lastEncryptedPartLen)
    {
        lastEncryptedPartLen = (NativeCULong)lastEncryptedPart.Length;
        ThrowIfUnbound(_fp.C_EncryptFinal);
        fixed (byte* partPtr = lastEncryptedPart)
        fixed (NativeCULong* lenPtr = &lastEncryptedPartLen)
            return _fp.C_EncryptFinal(session, partPtr, lenPtr);
    }
}
