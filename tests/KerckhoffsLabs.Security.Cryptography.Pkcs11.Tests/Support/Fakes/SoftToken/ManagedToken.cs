
namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

/// <summary>
/// Convenience entry points for opening a session over an in-process <see cref="ManagedSoftToken"/>.
/// Usage: <c>using var lib = ManagedToken.NewLibrary(); using var ws = ManagedToken.OpenSession(lib);</c>
/// (declare the library first so the session — declared second — disposes first). Disposing the
/// library finalizes the token's module and releases it, so a test using these belongs to
/// <c>[Collection(FakeModuleCollection.Name)]</c> and must dispose the library.
/// </summary>
internal static class ManagedToken
{
    public static Pkcs11Library NewLibrary() => new ManagedSoftToken().Load();

    /// <summary>
    /// A read/write session of a user login (a share of the login held, if another session holds one): the token is
    /// logged out when the last such session is disposed.
    /// </summary>
    public static Pkcs11Session OpenSession(Pkcs11Library library, ICryptoPolicy? policy = null)
    {
        using Pkcs11Login login = library.GetSlotByTokenLabel(ManagedSoftToken.TokenLabel)
            .ShareOrLogin(() => new SecurePin("1234"));
        return login.OpenSession(SessionAccess.ReadWrite, policy);
    }
}
