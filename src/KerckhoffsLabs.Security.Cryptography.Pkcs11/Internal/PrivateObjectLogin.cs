using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// Ties a wrapper of a private token object to the login it was found or made under, and refuses its handle once
/// that login has ended.
/// </summary>
/// <remarks>
/// <para>
/// PKCS#11 v3.2 <c>C_Logout</c>: "all of the application's handles to private objects become invalid (even if a
/// user is later logged back into the token)". A module may then hand such a handle to another object, so a wrapper
/// that kept sending it could sign with or read an object the caller never chose. The wrapper keeps the
/// <see cref="LoginStamp"/> it was made under and checks it before every use, inside the session's lease, which
/// holds the login gate: no logout or login can land between the check and the native call.
/// </para>
/// <para>
/// <b>Which objects are private.</b> <c>CKA_PRIVATE</c> as the token reports it. When the token does not report
/// it (the attribute is invalid or unreadable for the object), a private key or secret key counts as private and
/// any other class as public: keys are where the spec's defaults and every real token make objects private, and
/// guessing "private" for a key costs at most a refusal after logout, while guessing "public" could send a stale
/// handle.
/// </para>
/// </remarks>
internal static class PrivateObjectLogin
{
    /// <summary>
    /// Whether an object counts as private: <paramref name="reported"/> <c>CKA_PRIVATE</c>, or by class when the
    /// token did not report it.
    /// </summary>
    internal static bool IsPrivate(bool? reported, CKO objectClass)
        => reported ?? objectClass is CKO.CKO_PRIVATE_KEY or CKO.CKO_SECRET_KEY;

    /// <summary>
    /// <c>CKA_PRIVATE</c> as read through the generic attribute reader, or <see langword="null"/> when the token did
    /// not report it, or not as one <c>CK_BBOOL</c>.
    /// </summary>
    internal static bool? Reported(ObjectAttribute attribute)
    {
        if (attribute.CannotBeRead)
            return null;
        try
        {
            return attribute.GetValueAsBool();
        }
        catch (Pkcs11AttributeException)
        {
            return null;
        }
    }

    /// <summary>
    /// Throws when <paramref name="isPrivate"/> and the login state <paramref name="stamp"/> recorded has ended.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The object is private and its login has ended.</exception>
    internal static void ThrowIfEnded(bool isPrivate, LoginStamp stamp, TokenLoginRecord record, string objectName)
    {
        if (isPrivate && !record.IsStillCurrent(stamp))
            throw Ended(objectName);
    }

    /// <summary>The refusal of a private object's handle after its login ended.</summary>
    /// <remarks>An <see cref="ObjectDisposedException"/>, like a destroyed object's: the wrapper is spent.</remarks>
    internal static ObjectDisposedException Ended(string objectName) => new(
        objectName,
        "The login this private object was found or made under has ended (logged out, or reported gone by the " +
        "module). PKCS#11 invalidates its handle for good, even after logging in again, so this wrapper can no " +
        "longer reach the token. Log in and open the object again.");
}
