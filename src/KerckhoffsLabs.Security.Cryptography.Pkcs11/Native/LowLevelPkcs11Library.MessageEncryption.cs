using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins an AEAD encrypt-message sequence (PKCS#11 v3.0 §5.9.4). Pair with C_EncryptMessage or C_EncryptMessageBegin/Next + C_MessageEncryptFinal.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var messageEncryptInit = call.Functions.C_MessageEncryptInit;
        if (messageEncryptInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (Pkcs11Marshal.IsWindows)
        {
            CK_MECHANISM_Windows packed = CK_MECHANISM_Windows.FromUnified(in mechanism);
            return messageEncryptInit(session, &packed, key).ToCKR();
        }
        fixed (CK_MECHANISM* m = &mechanism)
            return messageEncryptInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// One-shot AEAD encrypt of a message (PKCS#11 v3.0 §5.9.5). parameter holds the per-message nonce/IV.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, bool lengthOnly, out NativeCULong ciphertextLen)
    {
        using ModuleCall call = EnterModule();
        var encryptMessage = call.Functions.C_EncryptMessage;
        ciphertextLen = (NativeCULong)ciphertext.Length;
        if (encryptMessage is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* adPtr = &NonNullPinnable(associatedData))
        fixed (byte* ptPtr = &NonNullPinnable(plaintext))
        fixed (byte* ctPtr = &NonNullPinnable(ciphertext))
        fixed (NativeCULong* lenPtr = &ciphertextLen)
        {
            rv = encryptMessage(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length,
                ptPtr, (NativeCULong)plaintext.Length, lengthOnly ? null : ctPtr, lenPtr).ToCKR();
        }
        return CheckedOutput(rv, lengthOnly, ciphertextLen, ciphertext.Length);
    }

    /// <summary>
    /// Begins a streaming AEAD encrypt (PKCS#11 v3.0 §5.9.6); follow with C_EncryptMessageNext calls.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData)
    {
        using ModuleCall call = EnterModule();
        var encryptMessageBegin = call.Functions.C_EncryptMessageBegin;
        if (encryptMessageBegin is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* adPtr = associatedData)
            return encryptMessageBegin(session, parameter, parameterLen, adPtr, (NativeCULong)associatedData.Length).ToCKR();
    }

    /// <summary>
    /// Encrypts a plaintext chunk in a streaming AEAD encrypt (PKCS#11 v3.0 §5.9.7). Pass CKF_END_OF_MESSAGE in flags on the final chunk.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> plaintextPart,
        Span<byte> ciphertextPart, bool lengthOnly, out NativeCULong ciphertextPartLen, NativeCULong flags)
    {
        using ModuleCall call = EnterModule();
        var encryptMessageNext = call.Functions.C_EncryptMessageNext;
        ciphertextPartLen = (NativeCULong)ciphertextPart.Length;
        if (encryptMessageNext is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* ptPtr = plaintextPart)
        fixed (byte* ctPtr = &NonNullPinnable(ciphertextPart))
        fixed (NativeCULong* lenPtr = &ciphertextPartLen)
        {
            rv = encryptMessageNext(session, parameter, parameterLen, ptPtr, (NativeCULong)plaintextPart.Length,
                lengthOnly ? null : ctPtr, lenPtr, flags).ToCKR();
        }
        return CheckedOutput(rv, lengthOnly, ciphertextPartLen, ciphertextPart.Length);
    }

    /// <summary>
    /// Ends an AEAD encrypt-message sequence on the session (PKCS#11 v3.0 §5.9.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageEncryptFinal(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var messageEncryptFinal = call.Functions.C_MessageEncryptFinal;
        if (messageEncryptFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return messageEncryptFinal(session).ToCKR();
    }
}
