using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// MD5Pkcs11 is [Obsolete] (broken crypto); the gate is the point of the type, so KLPKCS11001 is
// suppressed deliberately at the use sites.
#pragma warning disable KLPKCS11001

/// <summary>
/// MD5Pkcs11 over the in-process <c>ManagedSoftToken</c> — runs without SoftHSM. The secure-defaults
/// gate blocks MD5 by default (analogous to <c>MD5Cng</c> under FIPS); <c>AllowInsecureScope</c>
/// unlocks token-computed MD5 (<c>CKM_MD5</c>) and every result is cross-checked against the BCL
/// <see cref="MD5"/> primitive (RFC 1321). MD5 is always supported by the BCL, so the
/// <see cref="Supported"/> gate is harmless but kept for symmetry with the other digest adapters.
/// </summary>
public sealed class MD5Pkcs11_Managed
{
    public static bool Supported => true;

    private static Pkcs11Workspace OpenWorkspace(Pkcs11Library library) =>
        ManagedToken.OpenWorkspace(library);

    // === The gate: MD5 is blocked by default, unlocked only inside an insecure scope =======

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_GatedByDefault_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var md5 = new MD5Pkcs11(workspace);

        var ex = Assert.Throws<InsecureOperationException>(
            () => md5.ComputeHash(Encoding.UTF8.GetBytes("abc")));
        Assert.Equal(CKM.CKM_MD5, ex.Mechanism);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_OutsideScope_AfterScopeClosed_Throws()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var md5 = new MD5Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        using (workspace.AllowInsecureScope())
        {
            _ = md5.ComputeHash(data); // allowed
        }

        // The scope disposed and restored the gate, so a second compute must throw again.
        var ex = Assert.Throws<InsecureOperationException>(() => md5.ComputeHash(data));
        Assert.Equal(CKM.CKM_MD5, ex.Mechanism);
    }

    // === Known-answer + BCL cross-checks (computed inside the insecure scope) ==============

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_WithAllowInsecureScope_KnownAnswer_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var md5 = new MD5Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("abc");
        // RFC 1321 / BCL: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        byte[] expected = Convert.FromHexString("900150983CD24FB0D6963F7D28E17F72");

        using (workspace.AllowInsecureScope())
        {
            byte[] digest = md5.ComputeHash(data);
            Assert.Equal(16, digest.Length);
            Assert.Equal(expected, digest);
            Assert.Equal(MD5.HashData(data), digest);
        }
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_WithAllowInsecureFlag_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        workspace.AllowInsecure = true;
        using var md5 = new MD5Pkcs11(workspace);

        byte[] data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        // RFC 1321 test suite vector.
        byte[] expected = Convert.FromHexString("9E107D9D372BB6826BD81D3542A419D6");

        byte[] digest = md5.ComputeHash(data);
        Assert.Equal(expected, digest);
        Assert.Equal(MD5.HashData(data), digest);
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_EmptyInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var md5 = new MD5Pkcs11(workspace);

        // RFC 1321 / BCL: MD5("") = d41d8cd98f00b204e9800998ecf8427e
        byte[] expected = Convert.FromHexString("D41D8CD98F00B204E9800998ECF8427E");

        using (workspace.AllowInsecureScope())
        {
            byte[] digest = md5.ComputeHash([]);
            Assert.Equal(expected, digest);
            Assert.Equal(MD5.HashData([]), digest);
        }
    }

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_RandomInput_MatchesBcl()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var md5 = new MD5Pkcs11(workspace);

        byte[] data = RandomNumberGenerator.GetBytes(517);
        using (workspace.AllowInsecureScope())
            Assert.Equal(MD5.HashData(data), md5.ComputeHash(data));
    }

    // === Streaming / reuse ================================================================

    [ConditionalFact(nameof(Supported))]
    public void ComputeHash_Streamed_MatchesOneShot()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var md5 = new MD5Pkcs11(workspace);

        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        using (workspace.AllowInsecureScope())
        {
            md5.TransformBlock(part1, 0, part1.Length, null, 0);
            md5.TransformFinalBlock(part2, 0, part2.Length);
        }
        byte[] streamed = md5.Hash!;

        Assert.Equal(MD5.HashData(Encoding.UTF8.GetBytes("hello world")), streamed);
    }

    [ConditionalFact(nameof(Supported))]
    public void Reuse_AfterInitialize_ProducesFreshHash()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = OpenWorkspace(library);
        using var md5 = new MD5Pkcs11(workspace);

        using (workspace.AllowInsecureScope())
        {
            byte[] first = md5.ComputeHash(Encoding.UTF8.GetBytes("one"));
            byte[] second = md5.ComputeHash(Encoding.UTF8.GetBytes("two")); // ComputeHash calls Initialize
            Assert.Equal(MD5.HashData(Encoding.UTF8.GetBytes("one")), first);
            Assert.Equal(MD5.HashData(Encoding.UTF8.GetBytes("two")), second);
        }
    }

    // === Construction and argument validation (run before any native call) ================

    [Fact]
    public void Ctor_NullWorkspace_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new MD5Pkcs11(null!));
        Assert.Equal("workspace", ex.ParamName);
    }
}
#pragma warning restore KLPKCS11001
