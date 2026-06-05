using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// SHA3_256Pkcs11 over the in-process <c>ManagedSoftToken</c>. SoftHSM does not implement
/// <c>CKM_SHA3_256</c>, so this is exactly the kind of KAT the managed token unlocks — it runs
/// wherever the host BCL has SHA-3 (OpenSSL 3.x / Windows 11+), gated on <see cref="SHA3_256.IsSupported"/>.
/// </summary>
public sealed class SHA3_256Pkcs11Tests_Managed
{
    public static bool Sha3Supported => SHA3_256.IsSupported;

    [ConditionalFact(nameof(Sha3Supported))]
    public void ComputeHash_MatchesBcl_OverManagedToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("managed SHA-3 over a mechanism SoftHSM does not provide");
        Assert.Equal(SHA3_256.HashData(data), sha.ComputeHash(data));
    }

    [ConditionalFact(nameof(Sha3Supported))]
    public void ComputeHash_KnownAnswer_EmptyInput()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var sha = new SHA3_256Pkcs11(workspace);

        // NIST: SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        byte[] digest = sha.ComputeHash([]);
        Assert.Equal(
            Convert.FromHexString("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"),
            digest);
    }
}
