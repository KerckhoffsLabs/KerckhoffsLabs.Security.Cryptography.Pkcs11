using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// The obsolete instance constructors are the subject under test, and MD5 drives their
// unsupported-hash rejection.
#pragma warning disable KLPKCS11011, KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The <see cref="Rfc2898DeriveBytesPkcs11"/> constructors write the password straight into the
/// instance's pinned buffer. Runs on the in-process token, which does not implement
/// <c>CKM_PKCS5_PBKD2</c>: the password is captured from the parameters while the policy judges the
/// call, before the token refuses it.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Rfc2898DeriveBytesPkcs11ConstructionTests
{
    private static readonly byte[] Salt = new byte[16];

    /// <summary>Allows everything, and records the password each PBKDF2 mechanism would send.</summary>
    private sealed class PasswordCapturingPolicy : ICryptoPolicy
    {
        public List<byte[]> Passwords { get; } = [];
        public List<CkmPkcs5Pbkd2Params> Parameters { get; } = [];
        public string Name => "PasswordCapturing";
        public bool AllowsOverride => true;

        public PolicyDecision Evaluate(PolicyRequest request)
        {
            if (request is MechanismUseRequest { Mechanism.Parameters: CkmPkcs5Pbkd2Params p })
            {
                Parameters.Add(p);
                using var scope = new MechanismParameterScope();
                var s = p.BuildMarshalable(scope).Read<CK_PKCS5_PBKD2_PARAMS2>();
                // An empty password marshals as a NULL pointer, the PKCS#11 encoding of an empty buffer.
                int length = (int)(ulong)s.PasswordLen;
                Passwords.Add(length == 0 ? [] : UnmanagedMemory.Read(s.Password, length));
            }
            return CryptoPolicy.AllowInsecure.Evaluate(request);
        }
    }

    private static byte[] PasswordSentBy(Func<Pkcs11Workspace, Rfc2898DeriveBytesPkcs11> create)
    {
        var policy = new PasswordCapturingPolicy();
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var kdf = create(workspace);

        var ex = Assert.IsType<Pkcs11Exception>(Record.Exception(() => kdf.GetBytes(16)), exactMatch: false);
        Assert.Equal(CKR.CKR_MECHANISM_INVALID, ex.ReturnValue);
        return Assert.Single(policy.Passwords);
    }

    [Fact]
    public void StringConstructor_SendsTheUtf8Password() =>
        Assert.Equal("pässwörd"u8.ToArray(),
            PasswordSentBy(w => new Rfc2898DeriveBytesPkcs11(w, "pässwörd", Salt, 1000, HashAlgorithmName.SHA256)));

    [Fact]
    public void SpanConstructor_SendsThePassword() =>
        Assert.Equal("password"u8.ToArray(),
            PasswordSentBy(w => new Rfc2898DeriveBytesPkcs11(w, "password"u8, Salt, 1000, HashAlgorithmName.SHA256)));

    [Fact]
    public void ArrayConstructor_CopiesThePassword()
    {
        byte[] password = "password"u8.ToArray();

        byte[] sent = PasswordSentBy(w =>
        {
            var kdf = new Rfc2898DeriveBytesPkcs11(w, password, Salt, 1000, HashAlgorithmName.SHA256);
            password.AsSpan().Clear(); // the instance kept its own copy
            return kdf;
        });

        Assert.Equal("password"u8.ToArray(), sent);
    }

    [Fact]
    public void EmptyPassword_IsAccepted() =>
        Assert.Empty(PasswordSentBy(w => new Rfc2898DeriveBytesPkcs11(w, "", Salt, 1000, HashAlgorithmName.SHA256)));

    [Fact]
    public void InvalidArguments_AreRejected()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);

        Assert.Throws<ArgumentNullException>(() => new Rfc2898DeriveBytesPkcs11(null!, "pw", Salt, 1000, HashAlgorithmName.SHA256));
        Assert.Throws<ArgumentNullException>(() => new Rfc2898DeriveBytesPkcs11(workspace, (string)null!, Salt, 1000, HashAlgorithmName.SHA256));
        Assert.Throws<ArgumentNullException>(() => new Rfc2898DeriveBytesPkcs11(workspace, "pw", null!, 1000, HashAlgorithmName.SHA256));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Rfc2898DeriveBytesPkcs11(workspace, "pw"u8, Salt, 0, HashAlgorithmName.SHA256));
        Assert.Throws<NotSupportedException>(() => new Rfc2898DeriveBytesPkcs11(workspace, "pw"u8, Salt, 1000, HashAlgorithmName.MD5));
    }

    [Fact]
    public void AfterDispose_GetBytesThrows_AndDisposeIsIdempotent()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        var kdf = new Rfc2898DeriveBytesPkcs11(workspace, "pw", Salt, 1000, HashAlgorithmName.SHA256);

        kdf.Dispose();
        kdf.Dispose();

        Assert.Throws<ObjectDisposedException>(() => kdf.GetBytes(16));
    }

    // === The password is borrowed, not copied ================================

    private static bool StillMarshals(CkmPkcs5Pbkd2Params p)
    {
        using var scope = new MechanismParameterScope();
        try
        {
            p.BuildMarshalable(scope);
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
    }

    [Fact]
    public void Instance_LendsItsPasswordUntilDisposed()
    {
        var policy = new PasswordCapturingPolicy();
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        var kdf = new Rfc2898DeriveBytesPkcs11(workspace, "password", Salt, 1000, HashAlgorithmName.SHA256);
        Assert.ThrowsAny<Pkcs11Exception>(() => kdf.GetBytes(16));
        CkmPkcs5Pbkd2Params borrowed = Assert.Single(policy.Parameters);

        Assert.True(StillMarshals(borrowed));
        kdf.Dispose();
        Assert.False(StillMarshals(borrowed));
    }

    [Fact]
    public void OneShots_ReleaseTheirPasswordBeforeReturning()
    {
        var policy = new PasswordCapturingPolicy();
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library, policy);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        Assert.ThrowsAny<Pkcs11Exception>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2(workspace, "password", Salt, 1000, HashAlgorithmName.SHA256, 16));
        Assert.ThrowsAny<Pkcs11Exception>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2(workspace, "password"u8, Salt, new byte[16], 1000, HashAlgorithmName.SHA256));
        Assert.ThrowsAny<Pkcs11Exception>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2Key(workspace, "password"u8, Salt, 1000, HashAlgorithmName.SHA256, template));

        using (var password = new SecurePassword("password"))
        {
            Assert.ThrowsAny<Pkcs11Exception>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2Key(workspace, password, Salt, 1000, HashAlgorithmName.SHA256, template));
            Assert.True(StillMarshals(policy.Parameters[^1])); // borrowed from the caller, who has not disposed it yet
        }

        Assert.Equal(4, policy.Parameters.Count);
        Assert.All(policy.Parameters, p => Assert.False(StillMarshals(p)));
        Assert.All(policy.Passwords, p => Assert.Equal("password"u8.ToArray(), p));
    }
}
