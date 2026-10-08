using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Creates a new object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="template">Object's template</param>
    /// <param name="objectId">Location that receives the new object's handle</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_CreateObject(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong objectId)
    {
        using ModuleCall call = EnterModule();
        var createObject = call.Functions.C_CreateObject;
        if (createObject is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        // Windows modules read the Pack=1 layout; elsewhere the template is passed as it is.
        CK_ATTRIBUTE_Windows[]? packedTemplate = Pkcs11Marshal.IsWindows ? ToWindowsTemplate(template) : null;
        fixed (CK_ATTRIBUTE* t = template)
        fixed (CK_ATTRIBUTE_Windows* tw = packedTemplate)
        fixed (NativeCULong* idPtr = &objectId)
            return createObject(session, Pkcs11Marshal.IsWindows ? tw : t, (NativeCULong)template.Length, idPtr).ToCKR();
    }

    /// <summary>
    /// Copies an object, creating a new object for the copy
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template for the new object</param>
    /// <param name="newObjectId">Location that receives the handle for the copy of the object</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong newObjectId)
    {
        using ModuleCall call = EnterModule();
        var copyObject = call.Functions.C_CopyObject;
        if (copyObject is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        // Windows modules read the Pack=1 layout; elsewhere the template is passed as it is.
        CK_ATTRIBUTE_Windows[]? packedTemplate = Pkcs11Marshal.IsWindows ? ToWindowsTemplate(template) : null;
        fixed (CK_ATTRIBUTE* t = template)
        fixed (CK_ATTRIBUTE_Windows* tw = packedTemplate)
        fixed (NativeCULong* idPtr = &newObjectId)
            return copyObject(session, objectId, Pkcs11Marshal.IsWindows ? tw : t, (NativeCULong)template.Length, idPtr).ToCKR();
    }

    /// <summary>
    /// Destroys an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TOKEN_WRITE_PROTECTED</returns>
    public unsafe CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        using ModuleCall call = EnterModule();
        var destroyObject = call.Functions.C_DestroyObject;
        if (destroyObject is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return destroyObject(session, objectId).ToCKR();
    }

    /// <summary>
    /// Gets the size of an object in bytes
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="size">Location that receives the size in bytes of the object</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_INFORMATION_SENSITIVE, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
    {
        using ModuleCall call = EnterModule();
        var getObjectSize = call.Functions.C_GetObjectSize;
        if (getObjectSize is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        fixed (NativeCULong* sizePtr = &size)
            return getObjectSize(session, objectId, sizePtr).ToCKR();
    }

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template that specifies which attribute values are to be obtained, and receives the attribute values</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
    {
        using ModuleCall call = EnterModule();
        var getAttributeValue = call.Functions.C_GetAttributeValue;
        if (getAttributeValue is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        if (!Pkcs11Marshal.IsWindows)
        {
            fixed (CK_ATTRIBUTE* t = template)
                return getAttributeValue(session, objectId, t, (NativeCULong)template.Length).ToCKR();
        }

        // The module writes each value's length back into the packed copy, so the copy is mirrored
        // into the caller's template afterwards.
        CK_ATTRIBUTE_Windows[]? packedTemplate = ToWindowsTemplate(template);
        CKR rv;
        fixed (CK_ATTRIBUTE_Windows* tw = packedTemplate)
            rv = getAttributeValue(session, objectId, tw, (NativeCULong)template.Length).ToCKR();
        if (packedTemplate is not null)
            for (int i = 0; i < packedTemplate.Length; i++)
                template[i] = packedTemplate[i].ToUnified();
        return rv;
    }

    /// <summary>
    /// Modifies the value of one or more attributes of an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template that specifies which attribute values are to be modified and their new values</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public unsafe CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        using ModuleCall call = EnterModule();
        var setAttributeValue = call.Functions.C_SetAttributeValue;
        if (setAttributeValue is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        // Windows modules read the Pack=1 layout; elsewhere the template is passed as it is.
        CK_ATTRIBUTE_Windows[]? packedTemplate = Pkcs11Marshal.IsWindows ? ToWindowsTemplate(template) : null;
        fixed (CK_ATTRIBUTE* t = template)
        fixed (CK_ATTRIBUTE_Windows* tw = packedTemplate)
            return setAttributeValue(session, objectId, Pkcs11Marshal.IsWindows ? tw : t, (NativeCULong)template.Length).ToCKR();
    }

    /// <summary>
    /// Initializes a search for token and session objects that match a template
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="template">Search template that specifies the attribute values to match</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        using ModuleCall call = EnterModule();
        var findObjectsInit = call.Functions.C_FindObjectsInit;
        if (findObjectsInit is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        // Windows modules read the Pack=1 layout; elsewhere the template is passed as it is.
        CK_ATTRIBUTE_Windows[]? packedTemplate = Pkcs11Marshal.IsWindows ? ToWindowsTemplate(template) : null;
        fixed (CK_ATTRIBUTE* t = template)
        fixed (CK_ATTRIBUTE_Windows* tw = packedTemplate)
            return findObjectsInit(session, Pkcs11Marshal.IsWindows ? tw : t, (NativeCULong)template.Length).ToCKR();
    }

    /// <summary>
    /// Continues a search for token and session objects that match a template, obtaining additional object handles
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objects">Receives the additional object handles; its length is the maximum number returned</param>
    /// <param name="objectCount">Receives the actual number of object handles returned</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_FindObjects(NativeCULong session, Span<NativeCULong> objects, out NativeCULong objectCount)
    {
        using ModuleCall call = EnterModule();
        var findObjects = call.Functions.C_FindObjects;
        objectCount = default;
        if (findObjects is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        CKR rv;
        fixed (NativeCULong* objPtr = objects)
        fixed (NativeCULong* countPtr = &objectCount)
            rv = findObjects(session, objPtr, (NativeCULong)(ulong)objects.Length, countPtr).ToCKR();
        return CheckedOutput(rv, lengthOnly: false, objectCount, objects.Length);
    }

    /// <summary>
    /// Terminates a search for token and session objects
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public unsafe CKR C_FindObjectsFinal(NativeCULong session)
    {
        using ModuleCall call = EnterModule();
        var findObjectsFinal = call.Functions.C_FindObjectsFinal;
        if (findObjectsFinal is null)
            return CKR.CKR_FUNCTION_NOT_SUPPORTED;

        return findObjectsFinal(session).ToCKR();
    }
}
