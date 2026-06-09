using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// HMAC against a second real backend (opencryptoki). The RFC 4231 known-answer test is an
/// independent fixed vector, so agreement here cross-validates the wrapper against an
/// implementation unrelated to SoftHSM.
/// </summary>
[Collection("OpenCryptoki")]
public sealed class HMACPkcs11Tests_OpenCryptoki(OpenCryptokiBackendFixture backend)
{
    private readonly OpenCryptokiBackendFixture _backend = backend;
    public static bool Available => OpenCryptokiBackendFixture.OpenCryptokiAvailable;

    private static byte[] H(string hex) => Convert.FromHexString(hex);

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter)) { k.Delete(); k.Dispose(); }
    }

    private void WithImportedHmacKey(byte[] rawKey, Action<Pkcs11Key> body)
    {
        if (!_backend.Supports(CKM.CKM_SHA256_HMAC))
            throw new SkipTestException("opencryptoki: CKM_SHA256_HMAC not available");
        using var workspace = OpenWorkspace();
        string label = $"octk-hmac-{Guid.NewGuid():N}";
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label(label).Value(rawKey).Sign().Verify().OnToken().Build();
        try
        {
            using var key = workspace.ImportKey(tpl);
            body(key);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    // HMAC-SHA256, RFC 4231 test case 6 (131-byte key, larger than the block size).
    [ConditionalFact(nameof(Available))]
    public void ComputeHash_HmacSha256_KnownAnswer()
    {
        byte[] key = new byte[131];
        Array.Fill(key, (byte)0xaa);
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = H("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        WithImportedHmacKey(key, k =>
        {
            using var hmac = new HMACPkcs11(k, HashAlgorithmName.SHA256);
            Assert.Equal(expected, hmac.ComputeHash(data));
        });
    }

    [ConditionalFact(nameof(Available))]
    public void ComputeHash_DifferentInputs_Differ()
    {
        byte[] key = new byte[64];
        Array.Fill(key, (byte)0x5c);
        WithImportedHmacKey(key, k =>
        {
            using var hmac = new HMACPkcs11(k, HashAlgorithmName.SHA256);
            byte[] a = hmac.ComputeHash(Encoding.UTF8.GetBytes("message A"));
            byte[] b = hmac.ComputeHash(Encoding.UTF8.GetBytes("message B"));
            Assert.NotEqual(a, b);
        });
    }
}
