// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins a message-signing sequence (PKCS#11 v3.0 §5.13.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageSignInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return _delegates.C_MessageSignInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// One-shot message sign (PKCS#11 v3.0 §5.13.7).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature,
        out NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_SignMessage)
        {
            signatureLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        NativeCULong rv = _delegates.C_SignMessage(session, parameter, parameterLen, data, signature, out signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming message sign (PKCS#11 v3.0 §5.13.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_SignMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_SignMessageBegin(session, parameter, parameterLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Signs a data chunk in a streaming message sign (PKCS#11 v3.0 §5.13.9). signature is only written on the last call when end-of-message is signaled.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature,
        out NativeCULong signatureLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_SignMessageNext)
        {
            signatureLen = (NativeCULong)0;
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;
        }

        NativeCULong rv = _delegates.C_SignMessageNext(session, parameter, parameterLen, data, signature, out signatureLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends a message-signing sequence on the session (PKCS#11 v3.0 §5.13.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageSignFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageSignFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_MessageSignFinal(session);
        return rv.ToCKR();
    }
}
