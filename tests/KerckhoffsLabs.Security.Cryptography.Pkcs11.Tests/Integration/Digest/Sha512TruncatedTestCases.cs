using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

// SHA-512/224 and its HMAC are refused under SecureOnly; they are the mechanisms under test.
#pragma warning disable KLPKCS11009, KLPKCS11010

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Digest;

/// <summary>
/// Backend-agnostic known-answer tests for SHA-512/224 and SHA-512/256 (FIPS 180-4 §6.7), as digests and as
/// HMACs. The BCL has neither, so the expected values are NIST's published "abc" examples and values computed
/// with OpenSSL 3.0.13 (<c>openssl dgst -sha512-224 / -sha512-256</c>, with <c>-mac HMAC</c> for the HMACs).
/// The session runs under <see cref="CryptoPolicy.AllowInsecure"/>, since SecureOnly refuses SHA-512/224.
/// </summary>
internal static class Sha512TruncatedTestCases
{
    private static readonly byte[] Abc = "abc"u8.ToArray();
    private static readonly byte[] TwoBlock = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"u8.ToArray();
    private static readonly byte[] HmacKey = [.. Enumerable.Repeat((byte)0x0b, 20)];
    private static readonly byte[] HmacData = Encoding.ASCII.GetBytes("Hi There");

    internal static void Assert_Sha512_224_Kat(IPkcs11Backend backend) =>
        AssertDigests(backend, CKM.CKM_SHA512_224,
            ("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa", Abc),
            ("e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174", TwoBlock));

    internal static void Assert_Sha512_256_Kat(IPkcs11Backend backend) =>
        AssertDigests(backend, CKM.CKM_SHA512_256,
            ("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", Abc),
            ("bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461", TwoBlock));

    internal static void Assert_HmacSha512_224_Kat(IPkcs11Backend backend) =>
        AssertHmac(backend, CKM.CKM_SHA512_224_HMAC, "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039");

    internal static void Assert_HmacSha512_256_Kat(IPkcs11Backend backend) =>
        AssertHmac(backend, CKM.CKM_SHA512_256_HMAC, "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab");

    private static void AssertDigests(IPkcs11Backend backend, CKM mechanism, params (string Expected, byte[] Data)[] vectors)
    {
        backend.RequireMechanism(mechanism);
        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        foreach (var (expected, data) in vectors)
            Assert.Equal(expected, Convert.ToHexString(session.Digest(new Mechanism(mechanism), data)), ignoreCase: true);
    }

    private static void AssertHmac(IPkcs11Backend backend, CKM mechanism, string expected)
    {
        backend.RequireMechanism(mechanism);
        using var session = backend.OpenSession();
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure);
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label($"kl-sha512t-{Guid.NewGuid():N}").Value(HmacKey).Sign().OnToken(backend.SupportsTokenObjects).Build();
        using var key = session.ImportKey(template);
        try
        {
            Assert.Equal(expected, Convert.ToHexString(key.Sign(new Mechanism(mechanism), HmacData)), ignoreCase: true);
        }
        finally { key.Destroy(); }
    }
}
