// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins an AEAD decrypt-message sequence (PKCS#11 v3.0 §5.10.4).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_MessageDecryptInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return call.Table.C_MessageDecryptInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// One-shot AEAD decrypt of a message (PKCS#11 v3.0 §5.10.5). Returns CKR_AEAD_DECRYPT_FAILED on tag-verification failure.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, byte[]? plaintext, out NativeCULong plaintextLen)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_DecryptMessage)
        {
            plaintextLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        NativeCULong rv = call.Table.C_DecryptMessage(session, parameter, parameterLen, associatedData, ciphertext, plaintext, out plaintextLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming AEAD decrypt (PKCS#11 v3.0 §5.10.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_DecryptMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = call.Table.C_DecryptMessageBegin(session, parameter, parameterLen, associatedData);
        return rv.ToCKR();
    }

    /// <summary>
    /// Decrypts a ciphertext chunk in a streaming AEAD decrypt (PKCS#11 v3.0 §5.10.7). Pass CKF_END_OF_MESSAGE in flags on the final chunk.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> ciphertextPart,
        Span<byte> plaintextPart, out NativeCULong plaintextPartLen, NativeCULong flags)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_DecryptMessageNext)
        {
            plaintextPartLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        NativeCULong rv = call.Table.C_DecryptMessageNext(session, parameter, parameterLen, ciphertextPart, plaintextPart, out plaintextPartLen, flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends an AEAD decrypt-message sequence on the session (PKCS#11 v3.0 §5.10.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageDecryptFinal(NativeCULong session)
    {
        using ModuleCall call = EnterModule();

        if (!call.Table.HasC_MessageDecryptFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = call.Table.C_MessageDecryptFinal(session);
        return rv.ToCKR();
    }
}
