// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins a message-verification sequence (PKCS#11 v3.0 §5.15.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageVerifyInit)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return _delegates.C_MessageVerifyInit(session, ref mechanism, key).ToCKR();
    }

    /// <summary>
    /// One-shot message verify (PKCS#11 v3.0 §5.15.7). Returns CKR_SIGNATURE_INVALID on a bad signature.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifyMessage)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifyMessage(session, parameter, parameterLen, data, signature);
        return rv.ToCKR();
    }

    /// <summary>
    /// Begins a streaming message verify (PKCS#11 v3.0 §5.15.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifyMessageBegin)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifyMessageBegin(session, parameter, parameterLen);
        return rv.ToCKR();
    }

    /// <summary>
    /// Verifies a data chunk in a streaming verify (PKCS#11 v3.0 §5.15.9).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_VerifyMessageNext)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_VerifyMessageNext(session, parameter, parameterLen, data, signature);
        return rv.ToCKR();
    }

    /// <summary>
    /// Ends a message-verification sequence on the session (PKCS#11 v3.0 §5.15.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public CKR C_MessageVerifyFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!_delegates.HasC_MessageVerifyFinal)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        NativeCULong rv = _delegates.C_MessageVerifyFinal(session);
        return rv.ToCKR();
    }
}
