// <auto-split-from LowLevelPkcs11Library.cs>
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Obtains a list of slots in the system
    /// </summary>
    /// <param name="tokenPresent">Indicates whether the list obtained includes only those slots with a token present (true) or all slots (false)</param>
    /// <param name="slotList">
    /// If set to null then the number of slots is returned in "count" parameter, without actually returning a list of slots.
    /// If not set to null then "count" parameter must contain the lenght of slotList array and slot list is returned in "slotList" parameter.
    /// </param>
    /// <param name="count">Location that receives the number of slots</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK</returns>
    public CKR C_GetSlotList(bool tokenPresent, NativeCULong[]? slotList, ref NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetSlotList(tokenPresent, slotList, ref count);
        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains information about a particular slot in the system
    /// </summary>
    /// <param name="slotId">The ID of the slot</param>
    /// <param name="info">Structure that receives the slot information</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID</returns>
    public CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GetSlotInfo(slotId, ref info).ToCKR();
    }

    /// <summary>
    /// Obtains information about a particular token in the system
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="info">Structure that receives the token information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GetTokenInfo(slotId, ref info).ToCKR();
    }

    /// <summary>
    /// Obtains a list of mechanism types supported by a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="mechanismList">
    /// If set to null then the number of mechanisms is returned in "count" parameter, without actually returning a list of mechanisms.
    /// If not set to null then "count" parameter must contain the lenght of mechanismList array and mechanism list is returned in "mechanismList" parameter.
    /// </param>
    /// <param name="count">Location that receives the number of mechanisms</param>
    /// <returns>CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // NULL_PTR form: the caller is probing for the mechanism count, so there is nothing to copy back.
        if (mechanismList is null)
            return _delegates.C_GetMechanismList(slotId, null, ref count).ToCKR();

        NativeCULong[] CULongList = new NativeCULong[mechanismList.Length];
        NativeCULong rv = _delegates.C_GetMechanismList(slotId, CULongList, ref count);

        for (int i = 0; i < mechanismList.Length; i++)
            // Deliberately an unvalidated cast, not ToCKM(): a token may report vendor-defined
            // mechanisms (>= CKM_VENDOR_DEFINED) that are not declared CKM members, and the
            // validating conversion would throw mid-enumeration.
            mechanismList[i] = (CKM)(ulong)CULongList[i];

        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains information about a particular mechanism possibly supported by a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="type">The type of mechanism</param>
    /// <param name="info">Structure that receives the mechanism information</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_GetMechanismInfo(NativeCULong slotId, CKM type, ref CK_MECHANISM_INFO info)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GetMechanismInfo(slotId, type.ToCULong(), ref info).ToCKR();
    }

    /// <summary>
    /// Initializes a token
    /// </summary>
    /// <param name="slotId">The ID of the token's slot</param>
    /// <param name="pin">SO's initial PIN or null to use protected authentication path (pinpad)</param>
    /// <param name="label">32-byte long label of the token which must be padded with blank characters</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_EXISTS, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD</returns>
    public CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_InitToken(slotId, pin, label);
        return rv.ToCKR();
    }

    /// <summary>
    /// Waits for a slot event, such as token insertion or token removal, to occur
    /// </summary>
    /// <param name="flags">Determines whether or not the C_WaitForSlotEvent call blocks (i.e., waits for a slot event to occur)</param>
    /// <param name="slot">Location which will receive the ID of the slot that the event occurred in</param>
    /// <param name="reserved">Reserved for future versions (should be null)</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_NO_EVENT, CKR_OK</returns>
    public CKR C_WaitForSlotEvent(NativeCULong flags, ref NativeCULong slot, IntPtr reserved)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_WaitForSlotEvent(flags, ref slot, reserved);
        return rv.ToCKR();
    }
}
