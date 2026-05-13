using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Routes a non-CKR_OK return value to the typed <see cref="Pkcs11Exception"/> subclass
/// that categorizes it. Called from <see cref="Pkcs11Exception.ThrowIfError(CKR, string)"/>.
/// </summary>
/// <remarks>
/// Categories follow PKCS#11 v3.1 §5.3 grouping. A value with no narrower category maps
/// to <see cref="Pkcs11UnclassifiedException"/>.
/// </remarks>
internal static class ExceptionMapper
{
    internal static Pkcs11Exception Map(CKR returnValue, string method)
        => returnValue switch
        {
            // CKR_PIN_* and CKR_USER_* → authentication
            CKR.CKR_PIN_INCORRECT
              or CKR.CKR_PIN_INVALID
              or CKR.CKR_PIN_LEN_RANGE
              or CKR.CKR_PIN_EXPIRED
              or CKR.CKR_PIN_LOCKED
              or CKR.CKR_PIN_TOO_WEAK
              or CKR.CKR_USER_ALREADY_LOGGED_IN
              or CKR.CKR_USER_NOT_LOGGED_IN
              or CKR.CKR_USER_PIN_NOT_INITIALIZED
              or CKR.CKR_USER_TYPE_INVALID
              or CKR.CKR_USER_ANOTHER_ALREADY_LOGGED_IN
              or CKR.CKR_USER_TOO_MANY_TYPES
                => new Pkcs11AuthenticationException(returnValue, method, message: null),

            // CKR_SESSION_* → session
            CKR.CKR_SESSION_CLOSED
              or CKR.CKR_SESSION_COUNT
              or CKR.CKR_SESSION_HANDLE_INVALID
              or CKR.CKR_SESSION_PARALLEL_NOT_SUPPORTED
              or CKR.CKR_SESSION_READ_ONLY
              or CKR.CKR_SESSION_EXISTS
              or CKR.CKR_SESSION_READ_ONLY_EXISTS
              or CKR.CKR_SESSION_READ_WRITE_SO_EXISTS
                => new Pkcs11SessionException(returnValue, method, message: null),

            // CKR_TOKEN_*, CKR_DEVICE_* → token/device
            CKR.CKR_TOKEN_NOT_PRESENT
              or CKR.CKR_TOKEN_NOT_RECOGNIZED
              or CKR.CKR_TOKEN_WRITE_PROTECTED
              or CKR.CKR_TOKEN_RESOURCE_EXCEEDED
              or CKR.CKR_DEVICE_ERROR
              or CKR.CKR_DEVICE_MEMORY
              or CKR.CKR_DEVICE_REMOVED
                => new Pkcs11TokenException(returnValue, method, message: null),

            // CKR_MECHANISM_*, CKR_KEY_FUNCTION_NOT_PERMITTED → mechanism
            CKR.CKR_MECHANISM_INVALID
              or CKR.CKR_MECHANISM_PARAM_INVALID
              or CKR.CKR_KEY_FUNCTION_NOT_PERMITTED
                => new Pkcs11MechanismException(returnValue, method, message: null),

            // CKR_OBJECT_*, CKR_ATTRIBUTE_* → object/attribute
            CKR.CKR_OBJECT_HANDLE_INVALID
              or CKR.CKR_ATTRIBUTE_READ_ONLY
              or CKR.CKR_ATTRIBUTE_SENSITIVE
              or CKR.CKR_ATTRIBUTE_TYPE_INVALID
              or CKR.CKR_ATTRIBUTE_VALUE_INVALID
                => new Pkcs11ObjectException(returnValue, method, message: null),

            // CKR_ARGUMENTS_BAD, CKR_DATA_*, CKR_BUFFER_TOO_SMALL → argument
            CKR.CKR_ARGUMENTS_BAD
              or CKR.CKR_DATA_INVALID
              or CKR.CKR_DATA_LEN_RANGE
              or CKR.CKR_BUFFER_TOO_SMALL
                => new Pkcs11ArgumentException(returnValue, method, message: null),

            _ => new Pkcs11UnclassifiedException(returnValue, method, message: null),
        };
}
