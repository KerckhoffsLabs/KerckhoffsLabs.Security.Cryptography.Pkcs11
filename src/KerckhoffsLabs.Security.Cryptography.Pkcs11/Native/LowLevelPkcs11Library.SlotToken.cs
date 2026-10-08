using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Obtains a list of slots in the system
    /// </summary>
    /// <param name="tokenPresent">Indicates whether the list obtained includes only those slots with a token present (true) or all slots (false)</param>
    /// <param name="slotList">
    /// Receives the slot list. When empty, it is passed as NULL and only the number of slots is returned in
    /// <paramref name="count"/>. Its length is the capacity the module is told.
    /// </param>
    /// <param name="count">Receives the number of slots</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK</returns>
    public unsafe CKR C_GetSlotList(bool tokenPresent, Span<NativeCULong> slotList, out NativeCULong count)
    {
        using ModuleCall call = EnterModule();
        var getSlotList = call.Functions.C_GetSlotList;
        count = (NativeCULong)(ulong)slotList.Length;
        if (getSlotList is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (NativeCULong* slotPtr = slotList)
        fixed (NativeCULong* countPtr = &count)
            rv = getSlotList((byte)(tokenPresent ? 1 : 0), slotPtr, countPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly: slotList.IsEmpty, count, slotList.Length);
    }

    /// <summary>
    /// Obtains information about a particular slot in the system
    /// </summary>
    /// <param name="slotId">The ID of the slot</param>
    /// <param name="info">Structure that receives the slot information</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID</returns>
    public unsafe CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
    {
        using ModuleCall call = EnterModule();
        var getSlotInfo = call.Functions.C_GetSlotInfo;
        if (getSlotInfo is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (!Pkcs11Marshal.IsWindows)
        {
            fixed (CK_SLOT_INFO* p = &info)
                return getSlotInfo(slotId, p).ToCKR();
        }

        CK_SLOT_INFO_Windows packed = default;
        CKR rv = getSlotInfo(slotId, &packed).ToCKR();
        info = packed.ToUnified();
        return rv;
    }

    /// <summary>
    /// Obtains information about a particular token in the system
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="info">Structure that receives the token information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        using ModuleCall call = EnterModule();
        var getTokenInfo = call.Functions.C_GetTokenInfo;
        if (getTokenInfo is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (!Pkcs11Marshal.IsWindows)
        {
            fixed (CK_TOKEN_INFO* p = &info)
                return getTokenInfo(slotId, p).ToCKR();
        }

        CK_TOKEN_INFO_Windows packed = default;
        CKR rv = getTokenInfo(slotId, &packed).ToCKR();
        info = packed.ToUnified();
        return rv;
    }

    /// <summary>
    /// Obtains a list of mechanism types supported by a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="mechanismList">
    /// Receives the mechanism list. When empty, it is passed as NULL and only the number of mechanisms is
    /// returned in <paramref name="count"/>. Its length is the capacity the module is told.
    /// </param>
    /// <param name="count">Receives the number of mechanisms</param>
    /// <returns>CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_GetMechanismList(NativeCULong slotId, Span<CKM> mechanismList, out NativeCULong count)
    {
        using ModuleCall call = EnterModule();
        var getMechanismList = call.Functions.C_GetMechanismList;
        count = (NativeCULong)(ulong)mechanismList.Length;
        if (getMechanismList is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        // NULL_PTR form: the caller is asking for the mechanism count, so there is nothing to copy back.
        if (mechanismList.IsEmpty)
        {
            CKR queried;
            fixed (NativeCULong* countPtr = &count)
                queried = getMechanismList(slotId, null, countPtr).ToCKR();
            return CheckedOutput(queried, lengthOnly: true, count, 0);
        }

        // CKM is 64-bit and CK_ULONG is not everywhere, so the module writes into a CK_ULONG buffer.
        NativeCULong[] culongList = new NativeCULong[mechanismList.Length];
        CKR rv;
        fixed (NativeCULong* listPtr = culongList)
        fixed (NativeCULong* countPtr = &count)
            rv = CheckedOutput(getMechanismList(slotId, listPtr, countPtr).ToCKR(), lengthOnly: false, count, culongList.Length);

        // Vendor-defined and not-yet-named mechanisms survive as unnamed CKM values. count reports the
        // entries actually handed back, which the destination's length may cap.
        int kept = MechanismList.Copy(culongList, (ulong)count, mechanismList);
        if (rv == CKR.CKR_OK)
            count = (NativeCULong)(ulong)kept;

        return rv;
    }

    /// <summary>
    /// Obtains information about a particular mechanism possibly supported by a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="type">The type of mechanism</param>
    /// <param name="info">Structure that receives the mechanism information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_GetMechanismInfo(NativeCULong slotId, CKM type, ref CK_MECHANISM_INFO info)
    {
        using ModuleCall call = EnterModule();
        var getMechanismInfo = call.Functions.C_GetMechanismInfo;
        if (getMechanismInfo is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (!Pkcs11Marshal.IsWindows)
        {
            fixed (CK_MECHANISM_INFO* p = &info)
                return getMechanismInfo(slotId, type.ToCULong(), p).ToCKR();
        }

        CK_MECHANISM_INFO_Windows packed = default;
        CKR rv = getMechanismInfo(slotId, type.ToCULong(), &packed).ToCKR();
        info = packed.ToUnified();
        return rv;
    }

    /// <summary>
    /// Initializes a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="pin">SO's initial PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="label">32-byte long label of the token which must be padded with blank characters</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="label"/> is not 32 bytes long.</exception>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_EXISTS, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public unsafe CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label)
    {
        using ModuleCall call = EnterModule();

        // CK_TOKEN_INFO.label and C_InitToken's pLabel: blank-padded, not NUL-terminated.
        const int TokenLabelLength = 32;
        if (label.Length != TokenLabelLength)
            throw new ArgumentOutOfRangeException(nameof(label), label.Length,
                $"The token label must be exactly {TokenLabelLength} bytes (blank-padded): C_InitToken reads that many.");

        var initToken = call.Functions.C_InitToken;
        if (initToken is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (byte* pinPtr = pin)
        fixed (byte* labelPtr = label)
            return initToken(slotId, pinPtr, (NativeCULong)pin.Length, labelPtr).ToCKR();
    }

    /// <summary>
    /// Waits for a slot event, such as token insertion or token removal, to occur
    /// </summary>
    /// <param name="flags">Determines whether or not the C_WaitForSlotEvent call blocks (i.e., waits for a slot event to occur)</param>
    /// <param name="slot">Location which will receive the ID of the slot that the event occurred in</param>
    /// <param name="reserved">Reserved for future versions (should be null)</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_NO_EVENT, CKR_OK</returns>
    /// <remarks>
    /// A blocking wait does not hold off <c>C_Finalize</c>: PKCS#11 has <c>C_Finalize</c> wake it with
    /// <c>CKR_CRYPTOKI_NOT_INITIALIZED</c>, the only way to end it without an event, so disposing the
    /// library while a thread waits ends the wait instead of waiting for it. On a module that may not be
    /// called concurrently the wait holds the module's call lock like any call, so nothing else reaches
    /// the module until it returns; <c>Pkcs11Library.WaitForSlotEvent</c> refuses to block there.
    /// </remarks>
    public unsafe CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved)
    {
        bool blocking = ((ulong)flags & CKF.CKF_DONT_BLOCK) == 0;
        using ModuleCall call = EnterModule(holdsOffFinalize: !blocking);
        var waitForSlotEvent = call.Functions.C_WaitForSlotEvent;
        if (waitForSlotEvent is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (NativeCULong* slotPtr = &slot)
            return waitForSlotEvent(flags, slotPtr, reserved).ToCKR();
    }
}
