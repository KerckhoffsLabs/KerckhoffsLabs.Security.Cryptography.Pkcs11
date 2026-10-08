using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins a message-verification sequence (PKCS#11 v3.0 §5.15.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageVerifyInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var messageVerifyInit = call.Functions.C_MessageVerifyInit;
        if (messageVerifyInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        return messageVerifyInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// One-shot message verify (PKCS#11 v3.0 §5.15.7). Returns CKR_SIGNATURE_INVALID on a bad signature.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using ModuleCall call = EnterModule();
        var verifyMessage = call.Functions.C_VerifyMessage;
        if (verifyMessage is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return verifyMessage(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length).ToCKR();
    }

    /// <summary>
    /// Begins a streaming message verify (PKCS#11 v3.0 §5.15.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        using ModuleCall call = EnterModule();
        var verifyMessageBegin = call.Functions.C_VerifyMessageBegin;
        if (verifyMessageBegin is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return verifyMessageBegin(session, parameter, parameterLen).ToCKR();
    }

    /// <summary>
    /// Verifies a data chunk in a streaming verify (PKCS#11 v3.0 §5.15.9).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        using ModuleCall call = EnterModule();
        var verifyMessageNext = call.Functions.C_VerifyMessageNext;
        if (verifyMessageNext is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = signature)
            return verifyMessageNext(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, sigPtr, (NativeCULong)signature.Length).ToCKR();
    }

    /// <summary>
    /// Ends a message-verification sequence on the session (PKCS#11 v3.0 §5.15.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageVerifyFinal(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var messageVerifyFinal = call.Functions.C_MessageVerifyFinal;
        if (messageVerifyFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return messageVerifyFinal(session).ToCKR();
    }
}
