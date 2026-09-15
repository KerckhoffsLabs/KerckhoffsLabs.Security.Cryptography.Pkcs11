// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins an AEAD encrypt-message sequence (PKCS#11 v3.0 §5.9.4). Pair with C_EncryptMessage or C_EncryptMessageBegin/Next + C_MessageEncryptFinal.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageEncryptInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return _delegates.C_MessageEncryptInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// One-shot AEAD encrypt of a message (PKCS#11 v3.0 §5.9.5). parameter holds the per-message nonce/IV.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext, byte[]? ciphertext, out NativeCULong ciphertextLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncryptMessage)
        {
            ciphertextLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        NativeCULong rv = _delegates.C_EncryptMessage(session, parameter, parameterLen, associatedData, plaintext, ciphertext, out ciphertextLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming AEAD encrypt (PKCS#11 v3.0 §5.9.6); follow with C_EncryptMessageNext calls.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncryptMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_EncryptMessageBegin(session, parameter, parameterLen, associatedData);
        return rv.ToCKR();
    }

    /// <summary>
    /// Encrypts a plaintext chunk in a streaming AEAD encrypt (PKCS#11 v3.0 §5.9.7). Pass CKF_END_OF_MESSAGE in flags on the final chunk.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> plaintextPart,
        Span<byte> ciphertextPart, out NativeCULong ciphertextPartLen, NativeCULong flags)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_EncryptMessageNext)
        {
            ciphertextPartLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        NativeCULong rv = _delegates.C_EncryptMessageNext(session, parameter, parameterLen, plaintextPart, ciphertextPart, out ciphertextPartLen, flags);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends an AEAD encrypt-message sequence on the session (PKCS#11 v3.0 §5.9.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageEncryptFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageEncryptFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_MessageEncryptFinal(session);
        return rv.ToCKR();
    }
}
