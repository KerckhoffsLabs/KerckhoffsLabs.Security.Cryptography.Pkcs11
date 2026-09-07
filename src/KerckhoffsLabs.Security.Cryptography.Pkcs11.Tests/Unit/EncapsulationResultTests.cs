using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="EncapsulationResult"/> in isolation: pairing, deconstruction, and the disposal
/// contract documented on the type (the caller owns <c>SharedSecret</c>; disposing the result
/// disposes the key). Constructed directly via the <c>internal</c> constructor (visible here via
/// <c>InternalsVisibleTo</c>) with a generic AES key standing in for a real KEM-produced one — the
/// result's own logic does not depend on how the key was produced, and ML-KEM's own encapsulate/
/// decapsulate correctness is covered separately in <c>Algorithms/MLKemPkcs11TestCases.cs</c>.
/// </summary>
public sealed class EncapsulationResultTests
{
    private static Pkcs11Workspace NewWorkspace(out Pkcs11Library library)
    {
        library = ManagedToken.NewLibrary();
        return ManagedToken.OpenWorkspace(library);
    }

    [Fact]
    public void Ctor_PairsCiphertextWithSharedSecret()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            using var key = workspace.GenerateAesKey(256, label: "encap-pair");
            byte[] ciphertext = [1, 2, 3, 4];

            var result = new EncapsulationResult(ciphertext, key);

            Assert.Same(ciphertext, result.Ciphertext);
            Assert.Same(key, result.SharedSecret);
        }
    }

    [Fact]
    public void Deconstruct_YieldsCiphertextAndSharedSecret()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            using var key = workspace.GenerateAesKey(256, label: "encap-deconstruct");
            byte[] ciphertext = [5, 6, 7];
            var result = new EncapsulationResult(ciphertext, key);

            var (ct, sharedSecret) = result;

            Assert.Same(ciphertext, ct);
            Assert.Same(key, sharedSecret);
        }
    }

    [Fact]
    public void Dispose_DisposesSharedSecret()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            var key = workspace.GenerateAesKey(256, label: "encap-dispose");
            var result = new EncapsulationResult([1], key);

            result.Dispose();

            Assert.Throws<ObjectDisposedException>(() => key.GetAttributeValue(CKA.CKA_LABEL));
        }
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        using var workspace = NewWorkspace(out var library);
        using (library)
        {
            var key = workspace.GenerateAesKey(256, label: "encap-dispose-twice");
            var result = new EncapsulationResult([1], key);

            result.Dispose();

            Assert.Null(Record.Exception(result.Dispose));
        }
    }

    [Fact]
    public void Default_IsInertAndDisposeIsNoOp()
    {
        var result = default(EncapsulationResult);

        Assert.Null(result.Ciphertext);
        Assert.Null(result.SharedSecret);
        Assert.Null(Record.Exception(result.Dispose));
    }
}
