namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The refusal a wrapper gives once its own <c>Destroy</c> has removed the token object.
/// </summary>
/// <remarks>
/// PKCS#11 v3.2 §4.4 lets a module hand a destroyed object's handle to a new object, so a wrapper that kept
/// sending it could sign with, read, or destroy an object the caller never chose. The wrapper therefore refuses
/// every further use that would reach the token. Only the wrapper that called <c>Destroy</c> can know this: another
/// wrapper over the same handle, or a destroy by another session or process, is invisible to it, since a handle
/// carries no generation.
/// </remarks>
internal static class DestroyedObject
{
    /// <summary>The exception for a use of <paramref name="objectName"/> after its own destroy.</summary>
    /// <remarks>An <see cref="ObjectDisposedException"/> (and so an <see cref="InvalidOperationException"/>): the
    /// wrapper is spent, exactly as after <c>Dispose</c>, and a caller catching either keeps working.</remarks>
    internal static ObjectDisposedException Exception(string objectName) => new(
        objectName,
        "The token object was removed by Destroy(). Its handle may now name a different object, so this " +
        "wrapper can no longer reach the token.");
}
