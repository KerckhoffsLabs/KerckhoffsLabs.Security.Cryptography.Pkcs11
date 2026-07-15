using System.Security.Cryptography;
using BclECCurve = System.Security.Cryptography.ECCurve;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic ECDiffieHellmanPkcs11 tests. Uses <c>CKM_ECDH1_DERIVE</c> with
/// <see cref="CKD.CKD_NULL"/> (raw secret on the token, KDF in managed code). A P-256 key pair is
/// generated on the token and the derived keys / raw secret are cross-checked against a BCL
/// <see cref="ECDiffieHellman"/> peer. Agreement cases skip where the backend does not advertise
/// EC key-pair generation + ECDH derivation; the non-EC-key constructor check runs anywhere.
/// </summary>
internal static class ECDiffieHellmanPkcs11TestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.OpenWorkspace();

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates a P-256 key pair on the token (private half CKA_DERIVE) and hands the adapter to the
    // body. Skips where the backend lacks EC key-pair generation or ECDH derivation.
    private static void WithEcdh(IPkcs11Backend backend, Action<ECDiffieHellmanPkcs11> body)
    {
        if (!backend.Supports(CKM.CKM_EC_KEY_PAIR_GEN) || !backend.Supports(CKM.CKM_ECDH1_DERIVE))
            throw new SkipTestException("Backend does not advertise CKM_EC_KEY_PAIR_GEN + CKM_ECDH1_DERIVE.");

        using var workspace = OpenWorkspace(backend);
        string label = $"ecdh-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).EcParams(TestKeys.EcP256Oid).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
            .Label(label).Id(id).Derive().Build();

        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var ecdh = new ECDiffieHellmanPkcs11(key);
            body(ecdh);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort */ }
            key.Dispose();
        }
    }

    internal static void Assert_Ctor_NonEcKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"ecdh-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken(backend.SupportsTokenObjects).Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new ECDiffieHellmanPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_DeriveKeyFromHash_AgreesWithBcl(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

            byte[] aliceKey = alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256);
            byte[] bobKey = bob.DeriveKeyFromHash(alice.PublicKey, HashAlgorithmName.SHA256);

            Assert.Equal(32, aliceKey.Length);
            Assert.Equal(bobKey, aliceKey);
        });

    internal static void Assert_DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
            byte[] prepend = [1, 2, 3];
            byte[] append = [9, 8, 7, 6];

            byte[] aliceKey = alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA384, prepend, append);
            byte[] bobKey = bob.DeriveKeyFromHash(alice.PublicKey, HashAlgorithmName.SHA384, prepend, append);

            Assert.Equal(bobKey, aliceKey);
        });

    internal static void Assert_DeriveKeyFromHmac_AgreesWithBcl(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
            byte[] hmacKey = [0xAA, 0xBB, 0xCC, 0xDD];

            byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);
            byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);

            Assert.Equal(bobKey, aliceKey);
        });

    internal static void Assert_DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

            byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);
            byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);

            Assert.Equal(bobKey, aliceKey);
        });

    internal static void Assert_DeriveRawSecretAgreement_MatchesBcl(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

            byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
            byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);

            Assert.Equal(32, aliceZ.Length);
            Assert.Equal(bobZ, aliceZ);
        });

    internal static void Assert_DeriveKeyMaterial_AgreesWithBcl(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);

            // DeriveKeyMaterial defaults to DeriveKeyFromHash with SHA-256.
            Assert.Equal(bob.DeriveKeyMaterial(alice.PublicKey), alice.DeriveKeyMaterial(bob.PublicKey));
        });

    internal static void Assert_PublicKey_ExportsTokenPoint(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            ECParameters fromExport = alice.ExportParameters(includePrivateParameters: false);
            ECParameters fromPublicKey = alice.PublicKey.ExportParameters();

            Assert.Equal(fromExport.Q.X, fromPublicKey.Q.X);
            Assert.Equal(fromExport.Q.Y, fromPublicKey.Q.Y);
            Assert.Equal(BclECCurve.NamedCurves.nistP256.Oid.Value, fromPublicKey.Curve.Oid.Value);
        });

    internal static void Assert_DeriveKeyTls_NotSupported(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
        {
            using var bob = ECDiffieHellman.Create(BclECCurve.NamedCurves.nistP256);
            Assert.Throws<NotSupportedException>(
                () => alice.DeriveKeyTls(bob.PublicKey, new byte[16], new byte[64]));
        });

    internal static void Assert_ExportParameters_Private_ThrowsInsecure(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
            Assert.Throws<InsecureOperationException>(() => alice.ExportParameters(includePrivateParameters: true)));

    internal static void Assert_ImportParameters_NotSupported(IPkcs11Backend backend) =>
        WithEcdh(backend, alice =>
            Assert.Throws<NotSupportedException>(() => alice.ImportParameters(new ECParameters())));
}
