using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

/// <summary>
/// Convenience entry points for opening a workspace over an in-process <see cref="ManagedSoftToken"/>.
/// Usage: <c>using var lib = ManagedToken.NewLibrary(); using var ws = ManagedToken.OpenWorkspace(lib);</c>
/// (declare the library first so the workspace — declared second — disposes first).
/// </summary>
internal static class ManagedToken
{
    public static Pkcs11Library NewLibrary() => new(new ManagedSoftToken());

    public static Pkcs11Workspace OpenWorkspace(Pkcs11Library library) =>
        library.OpenWorkspace(ManagedSoftToken.TokenLabel, CKU.CKU_USER, new SecurePin("1234"));
}
