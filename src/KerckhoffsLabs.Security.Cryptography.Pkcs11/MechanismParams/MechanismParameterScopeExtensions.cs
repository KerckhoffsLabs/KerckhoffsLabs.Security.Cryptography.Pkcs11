using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

/// <summary>Resolves key-valued mechanism parameters against the session a scope was created for.</summary>
internal static class MechanismParameterScopeExtensions
{
    /// <summary>
    /// The handle <paramref name="key"/> contributes to a parameter field, checked against the session
    /// performing this call.
    /// </summary>
    /// <param name="scope">The scope of the call.</param>
    /// <param name="key">The key the caller put in the parameter.</param>
    /// <param name="part">Which of the key's objects the field refers to.</param>
    /// <param name="paramName">The parameter-type argument the key was passed as, for the exception.</param>
    /// <exception cref="ObjectDisposedException">The scope or the key has been disposed.</exception>
    /// <exception cref="ArgumentException">The key belongs to another workspace, or lacks the requested object.</exception>
    /// <exception cref="InvalidOperationException">The scope was created without a session.</exception>
    public static NativeCULong KeyHandle(this MechanismParameterScope scope, Pkcs11Key key, KeyHandlePart part, string paramName)
    {
        scope.ThrowIfDisposed();
        if (scope is not SessionParameterScope { Session: var session })
            throw new InvalidOperationException("Key-valued mechanism parameters can only be marshalled for a session.");
        return (NativeCULong)key.ResolveParameterHandle(session, part, paramName).ObjectId;
    }
}
