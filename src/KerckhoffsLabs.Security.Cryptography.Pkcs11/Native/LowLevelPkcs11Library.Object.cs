// <auto-split-from LowLevelPkcs11Library.cs>
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
    public CKR C_CreateObject(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong objectId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_CreateObject(session, template, ref objectId).ToCKR();
    }

    /// <summary>
    /// Copies an object, creating a new object for the copy
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template for the new object</param>
    /// <param name="newObjectId">Location that receives the handle for the copy of the object</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_CopyObject(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template, ref NativeCULong newObjectId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_CopyObject(session, objectId, template, ref newObjectId).ToCKR();
    }

    /// <summary>
    /// Destroys an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TOKEN_WRITE_PROTECTED</returns>
    public CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_DestroyObject(session, objectId);
        return rv.ToCKR();
    }

    /// <summary>
    /// Gets the size of an object in bytes
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="size">Location that receives the size in bytes of the object</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_INFORMATION_SENSITIVE, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_GetObjectSize(NativeCULong session, NativeCULong objectId, ref NativeCULong size)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_GetObjectSize(session, objectId, ref size);
        return rv.ToCKR();
    }

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template that specifies which attribute values are to be obtained, and receives the attribute values</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectId, Span<CK_ATTRIBUTE> template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_GetAttributeValue(session, objectId, template).ToCKR();
    }

    /// <summary>
    /// Modifies the value of one or more attributes of an object
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">The object's handle</param>
    /// <param name="template">Template that specifies which attribute values are to be modified and their new values</param>
    /// <returns>CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY, CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_WRITE_PROTECTED, CKR_USER_NOT_LOGGED_IN</returns>
    public CKR C_SetAttributeValue(NativeCULong session, NativeCULong objectId, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_SetAttributeValue(session, objectId, template).ToCKR();
    }

    /// <summary>
    /// Initializes a search for token and session objects that match a template
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="template">Search template that specifies the attribute values to match</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_FindObjectsInit(NativeCULong session, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _delegates.C_FindObjectsInit(session, template).ToCKR();
    }

    /// <summary>
    /// Continues a search for token and session objects that match a template, obtaining additional object handles
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <param name="objectId">Location that receives the list (array) of additional object handles</param>
    /// <param name="maxObjectCount">The maximum number of object handles to be returned</param>
    /// <param name="objectCount">Location that receives the actual number of object handles returned</param>
    /// <returns>CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_FindObjects(NativeCULong session, NativeCULong[] objectId, NativeCULong maxObjectCount, ref NativeCULong objectCount)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_FindObjects(session, objectId, maxObjectCount, ref objectCount);
        return rv.ToCKR();
    }

    /// <summary>
    /// Terminates a search for token and session objects
    /// </summary>
    /// <param name="session">The session's handle</param>
    /// <returns>CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID</returns>
    public CKR C_FindObjectsFinal(NativeCULong session)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        NativeCULong rv = _delegates.C_FindObjectsFinal(session);
        return rv.ToCKR();
    }
}
