using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins an AEAD decrypt-message sequence (PKCS#11 v3.0 §5.10.4).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var messageDecryptInit = call.Functions.C_MessageDecryptInit;
        if (messageDecryptInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return messageDecryptInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return messageDecryptInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// One-shot AEAD decrypt of a message (PKCS#11 v3.0 §5.10.5). Returns CKR_AEAD_DECRYPT_FAILED on tag-verification failure.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, bool lengthOnly, out NativeCULong plaintextLen)
    {
        using ModuleCall call = EnterModule();
        var decryptMessage = call.Functions.C_DecryptMessage;
        plaintextLen = (NativeCULong)plaintext.Length;
        if (decryptMessage is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* adPtr = &NonNullPinnable(associatedData))
        fixed (byte* ctPtr = &NonNullPinnable(ciphertext))
        fixed (byte* ptPtr = &NonNullPinnable(plaintext))
        fixed (NativeCULong* lenPtr = &plaintextLen)
        {
            rv = decryptMessage(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length,
                ctPtr, (NativeCULong)ciphertext.Length, lengthOnly ? null : ptPtr, lenPtr).ToCKR();
        }
        return CheckedOutput(rv, lengthOnly, plaintextLen, plaintext.Length);
    }

    /// <summary>
    /// Begins a streaming AEAD decrypt (PKCS#11 v3.0 §5.10.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData)
    {
        using ModuleCall call = EnterModule();
        var decryptMessageBegin = call.Functions.C_DecryptMessageBegin;
        if (decryptMessageBegin is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* adPtr = associatedData)
            return decryptMessageBegin(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length).ToCKR();
    }

    /// <summary>
    /// Decrypts a ciphertext chunk in a streaming AEAD decrypt (PKCS#11 v3.0 §5.10.7). Pass CKF_END_OF_MESSAGE in flags on the final chunk.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> ciphertextPart,
        Span<byte> plaintextPart, bool lengthOnly, out NativeCULong plaintextPartLen, NativeCULong flags)
    {
        using ModuleCall call = EnterModule();
        var decryptMessageNext = call.Functions.C_DecryptMessageNext;
        plaintextPartLen = (NativeCULong)plaintextPart.Length;
        if (decryptMessageNext is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* ctPtr = ciphertextPart)
        fixed (byte* ptPtr = &NonNullPinnable(plaintextPart))
        fixed (NativeCULong* lenPtr = &plaintextPartLen)
        {
            rv = decryptMessageNext(session, parameter, parameterLen, ctPtr, (NativeCULong)ciphertextPart.Length,
                lengthOnly ? null : ptPtr, lenPtr, flags).ToCKR();
        }
        return CheckedOutput(rv, lengthOnly, plaintextPartLen, plaintextPart.Length);
    }

    /// <summary>
    /// Ends an AEAD decrypt-message sequence on the session (PKCS#11 v3.0 §5.10.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageDecryptFinal(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var messageDecryptFinal = call.Functions.C_MessageDecryptFinal;
        if (messageDecryptFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return messageDecryptFinal(session).ToCKR();
    }
}
