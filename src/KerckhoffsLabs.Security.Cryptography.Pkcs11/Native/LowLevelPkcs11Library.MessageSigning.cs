using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Begins a message-signing sequence (PKCS#11 v3.0 §5.13.6).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageSignInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key)
    {
        using ModuleCall call = EnterModule();
        var messageSignInit = call.Functions.C_MessageSignInit;
        if (messageSignInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        byte* m = stackalloc byte[Pkcs11Marshal.SizeOf<CK_MECHANISM>()];
        Pkcs11Marshal.WriteStructure((IntPtr)m, in mechanism);
        return messageSignInit(session, m, key).ToCKR();
    }

    /// <summary>
    /// One-shot message sign (PKCS#11 v3.0 §5.13.7).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature,
        bool lengthOnly, out NativeCULong signatureLen)
    {
        using ModuleCall call = EnterModule();
        var signMessage = call.Functions.C_SignMessage;
        signatureLen = (NativeCULong)signature.Length;
        if (signMessage is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = &NonNullPinnable(signature))
        fixed (NativeCULong* lenPtr = &signatureLen)
            rv = signMessage(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, lengthOnly ? null : sigPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, signatureLen, signature.Length);
    }

    /// <summary>
    /// Begins a streaming message sign (PKCS#11 v3.0 §5.13.8).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen)
    {
        using ModuleCall call = EnterModule();
        var signMessageBegin = call.Functions.C_SignMessageBegin;
        if (signMessageBegin is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return signMessageBegin(session, parameter, parameterLen).ToCKR();
    }

    /// <summary>
    /// Signs a data chunk in a streaming message sign (PKCS#11 v3.0 §5.13.9). signature is only written on the last call when end-of-message is signaled.
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, Span<byte> signature,
        bool lengthOnly, out NativeCULong signatureLen)
    {
        using ModuleCall call = EnterModule();
        var signMessageNext = call.Functions.C_SignMessageNext;
        signatureLen = (NativeCULong)signature.Length;
        if (signMessageNext is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (byte* dataPtr = data)
        fixed (byte* sigPtr = &NonNullPinnable(signature))
        fixed (NativeCULong* lenPtr = &signatureLen)
            rv = signMessageNext(session, parameter, parameterLen, dataPtr, (NativeCULong)data.Length, lengthOnly ? null : sigPtr, lenPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly, signatureLen, signature.Length);
    }

    /// <summary>
    /// Ends a message-signing sequence on the session (PKCS#11 v3.0 §5.13.10).
    /// </summary>
    /// <returns><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; otherwise the underlying PKCS#11 return code.</returns>
    public unsafe CKR C_MessageSignFinal(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var messageSignFinal = call.Functions.C_MessageSignFinal;
        if (messageSignFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return messageSignFinal(session).ToCKR();
    }
}
