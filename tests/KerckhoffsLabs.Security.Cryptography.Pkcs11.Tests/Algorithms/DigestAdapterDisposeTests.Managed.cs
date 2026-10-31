using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

// MD5Pkcs11 and SHA1Pkcs11 are [Obsolete] (broken crypto); they are named here only to dispose them.
#pragma warning disable KLPKCS11001, KLPKCS11002

/// <summary>
/// The buffering digest adapters (<see cref="MD5Pkcs11"/>, <see cref="SHA1Pkcs11"/>, <see cref="SHA256Pkcs11"/>,
/// <see cref="SHA384Pkcs11"/>, <see cref="SHA512Pkcs11"/>) over the in-process <c>ManagedSoftToken</c>:
/// what each <c>Dispose(bool)</c> override does on both of its paths.
/// </summary>
/// <remarks>
/// <c>Dispose(false)</c> is the finalizer path of the dispose pattern, where an object must not touch
/// other managed objects, which may already have been finalized. These types are sealed and declare no
/// finalizer, so no public call reaches that path; the test invokes the protected override by reflection,
/// the one way to run it, and checks that it leaves the input buffer alone: the instance still hashes,
/// and a later <c>Dispose()</c> still releases it.
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class DigestAdapterDispose_Managed
{
    public static TheoryData<string> Adapters() => ["MD5", "SHA1", "SHA256", "SHA384", "SHA512"];

    private static HashAlgorithm Create(string name, Pkcs11Session session) => name switch
    {
        "MD5" => new MD5Pkcs11(session),
        "SHA1" => new SHA1Pkcs11(session),
        "SHA256" => new SHA256Pkcs11(session),
        "SHA384" => new SHA384Pkcs11(session),
        "SHA512" => new SHA512Pkcs11(session),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
    };

    private static byte[] Oracle(string name, byte[] data) => name switch
    {
        "MD5" => MD5.HashData(data),
        "SHA1" => SHA1.HashData(data),
        "SHA256" => SHA256.HashData(data),
        "SHA384" => SHA384.HashData(data),
        "SHA512" => SHA512.HashData(data),
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
    };

    [Theory]
    [MemberData(nameof(Adapters))]
    public void DisposeFalse_LeavesTheBufferAlone_AndDisposeStillReleasesIt(string name)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        // MD5 and SHA-1 need the opt-in; it changes nothing for the SHA-2 family.
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        var hash = Create(name, session);

        // Leave input in the buffer, as a finalizer would find it mid-computation.
        byte[] part1 = Encoding.UTF8.GetBytes("hello ");
        byte[] part2 = Encoding.UTF8.GetBytes("world");
        hash.TransformBlock(part1, 0, part1.Length, null, 0);

        MethodInfo dispose = hash.GetType().GetMethod(
            "Dispose", BindingFlags.Instance | BindingFlags.NonPublic, [typeof(bool)])!;
        dispose.Invoke(hash, [false]);

        // The buffer was not disposed, and still holds the first part.
        hash.TransformFinalBlock(part2, 0, part2.Length);
        Assert.Equal(Oracle(name, Encoding.UTF8.GetBytes("hello world")), hash.Hash);

        hash.Dispose();
        Assert.Throws<ObjectDisposedException>(() => hash.ComputeHash(part1));
    }
}
#pragma warning restore KLPKCS11001, KLPKCS11002
