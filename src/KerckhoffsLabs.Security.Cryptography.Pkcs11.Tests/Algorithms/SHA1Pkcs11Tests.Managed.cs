using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// SHA1Pkcs11 is [Obsolete] (broken crypto); the secure-defaults gate is the point of the type, so
// CS0618 is suppressed deliberately at the use sites.
#pragma warning disable CS0618

/// <summary>
/// SHA1Pkcs11 over the in-process <c>ManagedSoftToken</c> — runs without SoftHSM. SHA-1 is broken and
/// the adapter is gated by the library's secure-defaults policy (analogous to <c>SHA1Cng</c> under
/// FIPS): computing a digest throws <see cref="InsecureOperationException"/> unless the workspace
/// opts in via <see cref="Pkcs11Workspace.AllowInsecure"/> /
/// <see cref="Pkcs11Workspace.AllowInsecureScope"/>. When unlocked, the token computes the digest via
/// <c>CKM_SHA_1</c> and every result is cross-checked against the BCL <see cref="SHA1"/> primitive
/// (FIPS 180-4).
/// </summary>
public sealed class SHA1Pkcs11_Managed
{
    public static bool Supported => true;

    private static Pkcs11Workspace OpenWorkspace(Pkcs11Library library) =>
        ManagedToken.OpenWorkspace(library);

    // === Secure-defaults gate: SHA-1 is blocked unless explicitly allowed =================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_GatedByDefault_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha1 = new SHA1Pkcs11(workspace);

        var ex = Assert.Throws<InsecureOperationException>(
            () => sha1.ComputeHash(Encoding.UTF8.GetBytes("abc")));
        Assert.Equal(CKM.CKM_SHA_1, ex.Mechanism);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_OutsideScope_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha1 = new SHA1Pkcs11(workspace);

        // Enter and leave an AllowInsecure scope, then confirm the gate is restored.
        using (workspace.AllowInsecureScope())
            sha1.ComputeHash(Encoding.UTF8.GetBytes("inside"));

        var ex = Assert.Throws<InsecureOperationException>(
            () => sha1.ComputeHash(Encoding.UTF8.GetBytes("outside")));
        Assert.Equal(CKM.CKM_SHA_1, ex.Mechanism);
    }

    // === Real crypto under the insecure opt-in: cross-checked against the BCL ==============

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_WithAllowInsecure_KnownAnswer_MatchesFips180Vector()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        // FIPS 180-4 / BCL: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        byte[] expected = Convert.FromHexString("A9993E364706816ABA3E25717850C26C9CD0D89D");
        byte[] digest = sha1.ComputeHash(data);

        Assert.Equal(20, digest.Length);
        Assert.Equal(expected, digest);
        Assert.Equal(SHA1.HashData(data), digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_WithAllowInsecureScope_KnownAnswer_MatchesFips180Vector()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        byte[] expected = Convert.FromHexString("A9993E364706816ABA3E25717850C26C9CD0D89D");

        byte[] digest;
        using (workspace.AllowInsecureScope())
            digest = sha1.ComputeHash(data);

        Assert.Equal(20, digest.Length);
        Assert.Equal(expected, digest);
        Assert.Equal(SHA1.HashData(data), digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_EmptyInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] digest = sha1.ComputeHash([]);

        // FIPS 180-4 / BCL: SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        byte[] expected = Convert.FromHexString("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        Assert.Equal(expected, digest);
        Assert.Equal(SHA1.HashData([]), digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_MatchesBclSha1()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        Assert.Equal(SHA1.HashData(data), sha1.ComputeHash(data));
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(517);
        Assert.Equal(SHA1.HashData(data), sha1.ComputeHash(data));
    }

    // === Streaming / reuse ===============================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        // Feed in chunks via TransformBlock/TransformFinalBlock; result must equal the one-shot hash.
        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        sha1.TransformBlock(part1, 0, part1.Length, null, 0);
        sha1.TransformFinalBlock(part2, 0, part2.Length);
        byte[] streamed = sha1.Hash!;

        Assert.Equal(SHA1.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(Supported))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        workspace.AllowInsecure = true;
        using var sha1 = new SHA1Pkcs11(workspace);

        byte[] first = sha1.ComputeHash(Encoding.UTF8.GetBytes("one"));
        byte[] second = sha1.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
        Assert.Equal(SHA1.HashData(Encoding.UTF8.GetBytes("one")), first);
        Assert.Equal(SHA1.HashData(Encoding.UTF8.GetBytes("two")), second);
    }

    // === Construction and argument validation (run before any native call) ================

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SHA1Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
#pragma warning restore CS0618
