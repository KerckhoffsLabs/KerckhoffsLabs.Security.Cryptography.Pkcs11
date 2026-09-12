using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// PBKDF2-HMAC-SHA1 is an RFC 8018-approved PRF (unlike using SHA1 directly for a signature or MAC),
// and this file also drives the ctor's unsupported-hash rejection with MD5 on purpose, so the
// compile-time warning is suppressed for this file only.
#pragma warning disable KLPKCS11010
// This file exercises the instance constructors on purpose (streaming GetBytes and their own
// argument-validation), even though they are [Obsolete] (KLPKCS11011) in favor of the static
// Pbkdf2 method.
#pragma warning disable KLPKCS11011

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic known-answer and behavioral tests for <see cref="Rfc2898DeriveBytesPkcs11"/>
/// (CKM_PKCS5_PBKD2 / RFC 8018 PBKDF2). Only Kryoptic and NSS implement this mechanism -- SoftHSM2
/// and opencryptoki's soft token never register it, so their test files skip everything here via
/// <c>RequireMechanism</c>. Expected outputs are cross-checked against the
/// BCL's <c>Rfc2898DeriveBytes.Pbkdf2</c> rather than hard-coded vectors, covering every PRF this
/// wrapper exposes (matching https://github.com/latchset/kryoptic/issues/277, which asks Kryoptic's
/// own suite to do the same).
/// </summary>
internal static class Rfc2898DeriveBytesPkcs11TestCases
{
    private static readonly byte[] Password = Encoding.UTF8.GetBytes("passwordPASSWORDpassword");
    private static readonly byte[] Salt = Encoding.UTF8.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
    private const int Iterations = 4096;

    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) => backend.OpenWorkspace();

    private static Rfc2898DeriveBytesPkcs11 NewKdf(Pkcs11Workspace workspace, HashAlgorithmName hash, byte[]? password = null, byte[]? salt = null, int iterations = Iterations)
    {
        // Every derivation reads CKA_VALUE back off the token, so the gate in BuildSecureKeyDefaults
        // refuses the extractable, non-sensitive key it needs. Opt in here.
        workspace.AllowInsecure = true;
        return new Rfc2898DeriveBytesPkcs11(workspace, password ?? Password, salt ?? Salt, iterations, hash);
    }

    private static byte[] GetBytes(IPkcs11Backend backend, HashAlgorithmName hash, int count, byte[]? password = null, byte[]? salt = null, int iterations = Iterations)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        using var workspace = OpenWorkspace(backend);
        using var kdf = NewKdf(workspace, hash, password, salt, iterations);
        return kdf.GetBytes(count);
    }

    // RFC 6070's own vector (20-byte SHA1 PRF output), the one entry that also satisfies FIPS salt/
    // iteration-count minimums, so it runs unconditionally rather than being gated behind a "slow" flag.
    internal static void Assert_GetBytes_Sha1_MatchesRfc6070(IPkcs11Backend backend)
    {
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA1, 20);
        byte[] actual = GetBytes(backend, HashAlgorithmName.SHA1, 20);
        Assert.Equal(expected, actual);
    }

    internal static void Assert_GetBytes_Sha256_MatchesBcl(IPkcs11Backend backend)
    {
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA256, 32);
        byte[] actual = GetBytes(backend, HashAlgorithmName.SHA256, 32);
        Assert.Equal(expected, actual);
    }

    internal static void Assert_GetBytes_Sha384_MatchesBcl(IPkcs11Backend backend)
    {
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA384, 48);
        byte[] actual = GetBytes(backend, HashAlgorithmName.SHA384, 48);
        Assert.Equal(expected, actual);
    }

    internal static void Assert_GetBytes_Sha512_MatchesBcl(IPkcs11Backend backend)
    {
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA512, 64);
        byte[] actual = GetBytes(backend, HashAlgorithmName.SHA512, 64);
        Assert.Equal(expected, actual);
    }

    // A dkLen spanning more than one PRF output block per PRF (32 bytes for SHA256) exercises the
    // block-counter loop inside the token's PBKDF2 implementation, not just its first block.
    internal static void Assert_GetBytes_LongerThanOneBlock_MatchesBcl(IPkcs11Backend backend)
    {
        const int length = 96; // 3 SHA-256 blocks
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA256, length);
        byte[] actual = GetBytes(backend, HashAlgorithmName.SHA256, length);
        Assert.Equal(expected, actual);
    }

    internal static void Assert_GetBytes_EmptyPassword_MatchesBcl(IPkcs11Backend backend)
    {
        byte[] empty = [];
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(empty, Salt, Iterations, HashAlgorithmName.SHA256, 32);
        byte[] actual = GetBytes(backend, HashAlgorithmName.SHA256, 32, password: empty);
        Assert.Equal(expected, actual);
    }

    // Two derivations that differ only in PRF must not collide.
    internal static void Assert_GetBytes_DifferentPrf_ProducesDifferentOutput(IPkcs11Backend backend)
    {
        byte[] sha256 = GetBytes(backend, HashAlgorithmName.SHA256, 32);
        byte[] sha384 = GetBytes(backend, HashAlgorithmName.SHA384, 32);
        Assert.NotEqual(sha256, sha384);
    }

    // GetBytes must return successive slices of one continuous stream, matching the BCL: concatenating
    // two 16-byte calls must equal a single 32-byte derivation.
    internal static void Assert_GetBytes_SuccessiveCalls_ContinueOneStream(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        using var workspace = OpenWorkspace(backend);
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA256, 32);

        using var kdf = NewKdf(workspace, HashAlgorithmName.SHA256);
        byte[] first = kdf.GetBytes(16);
        byte[] second = kdf.GetBytes(16);

        byte[] combined = [.. first, .. second];
        Assert.Equal(expected, combined);
    }

    // Setting Salt mid-stream must restart the stream from the beginning, matching the BCL.
    internal static void Assert_GetBytes_AfterSettingSalt_RestartsStream(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        using var workspace = OpenWorkspace(backend);
        using var kdf = NewKdf(workspace, HashAlgorithmName.SHA256);

        byte[] first = kdf.GetBytes(16);
        kdf.Salt = Salt; // same value, but the setter must still restart the stream
        byte[] second = kdf.GetBytes(16);

        Assert.Equal(first, second);
    }

    // Reset() must restart the stream from the beginning, matching the BCL.
    internal static void Assert_Reset_RestartsStream(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        using var workspace = OpenWorkspace(backend);
        using var kdf = NewKdf(workspace, HashAlgorithmName.SHA256);

        byte[] first = kdf.GetBytes(16);
        kdf.Reset();
        byte[] second = kdf.GetBytes(16);

        Assert.Equal(first, second);
    }

    internal static void Assert_Ctor_NullWorkspace_Throws(IPkcs11Backend backend) =>
        Assert.Throws<ArgumentNullException>(() => new Rfc2898DeriveBytesPkcs11(null!, Password, Salt, Iterations, HashAlgorithmName.SHA256));

    internal static void Assert_Ctor_NullPassword_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentNullException>(() => new Rfc2898DeriveBytesPkcs11(workspace, (byte[])null!, Salt, Iterations, HashAlgorithmName.SHA256));
    }

    internal static void Assert_Ctor_NullSalt_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentNullException>(() => new Rfc2898DeriveBytesPkcs11(workspace, Password, null!, Iterations, HashAlgorithmName.SHA256));
    }

    internal static void Assert_Ctor_NonPositiveIterations_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentOutOfRangeException>(() => new Rfc2898DeriveBytesPkcs11(workspace, Password, Salt, 0, HashAlgorithmName.SHA256));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Rfc2898DeriveBytesPkcs11(workspace, Password, Salt, -1, HashAlgorithmName.SHA256));
    }

    internal static void Assert_Ctor_UnsupportedHash_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<NotSupportedException>(() => new Rfc2898DeriveBytesPkcs11(workspace, Password, Salt, Iterations, HashAlgorithmName.MD5));
    }

    internal static void Assert_GetBytes_NonPositiveCount_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var kdf = NewKdf(workspace, HashAlgorithmName.SHA256);
        Assert.Throws<ArgumentOutOfRangeException>(() => kdf.GetBytes(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => kdf.GetBytes(-1));
    }

    internal static void Assert_GetBytes_AfterDispose_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        var kdf = NewKdf(workspace, HashAlgorithmName.SHA256);
        kdf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => kdf.GetBytes(16));
    }

    internal static void Assert_HashAlgorithm_ReturnsConstructedValue(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        using var kdf = NewKdf(workspace, HashAlgorithmName.SHA384);
        Assert.Equal(HashAlgorithmName.SHA384, kdf.HashAlgorithm);
    }

    // === Static Pbkdf2 (the recommended, non-obsolete entry point) =======================

    internal static void Assert_StaticPbkdf2_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        using var workspace = OpenWorkspace(backend);
        workspace.AllowInsecure = true;

        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA256, 32);
        byte[] actual = Rfc2898DeriveBytesPkcs11.Pbkdf2(workspace, Password, Salt, Iterations, HashAlgorithmName.SHA256, 32);
        Assert.Equal(expected, actual);
    }

    internal static void Assert_StaticPbkdf2_DestinationSpan_MatchesBcl(IPkcs11Backend backend)
    {
        backend.RequireMechanism(CKM.CKM_PKCS5_PBKD2);
        using var workspace = OpenWorkspace(backend);
        workspace.AllowInsecure = true;

        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(Password, Salt, Iterations, HashAlgorithmName.SHA256, 32);
        byte[] actual = new byte[32];
        Rfc2898DeriveBytesPkcs11.Pbkdf2(workspace, Password, Salt, actual, Iterations, HashAlgorithmName.SHA256);
        Assert.Equal(expected, actual);
    }

    internal static void Assert_StaticPbkdf2_ZeroOutputLength_ReturnsEmptyWithNoTokenCall(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        // No RequireMechanism/AllowInsecure: a zero-length request must short-circuit before any
        // token call, so this must pass even on backends that do not implement CKM_PKCS5_PBKD2.
        byte[] actual = Rfc2898DeriveBytesPkcs11.Pbkdf2(workspace, Password, Salt, Iterations, HashAlgorithmName.SHA256, 0);
        Assert.Empty(actual);
    }

    internal static void Assert_StaticPbkdf2_NullWorkspace_Throws(IPkcs11Backend backend) =>
        Assert.Throws<ArgumentNullException>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2(null!, Password, Salt, Iterations, HashAlgorithmName.SHA256, 32));

    internal static void Assert_StaticPbkdf2_NegativeOutputLength_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<ArgumentOutOfRangeException>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2(workspace, Password, Salt, Iterations, HashAlgorithmName.SHA256, -1));
    }

    internal static void Assert_StaticPbkdf2_UnsupportedHash_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        Assert.Throws<NotSupportedException>(() => Rfc2898DeriveBytesPkcs11.Pbkdf2(workspace, Password, Salt, Iterations, HashAlgorithmName.MD5, 32));
    }
}
