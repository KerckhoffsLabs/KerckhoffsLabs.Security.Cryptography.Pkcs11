using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

public sealed class ECDiffieHellmanPkcs11ArgumentTests
{
    [Fact]
    public void Ctor_NullKey_Throws() =>
        Assert.Throws<ArgumentNullException>(() => new ECDiffieHellmanPkcs11(key: null!));
}

/// <summary>
/// ECDiffieHellmanPkcs11 over SoftHSM. SoftHSM implements <c>CKM_ECDH1_DERIVE</c> with
/// <see cref="CKD.CKD_NULL"/>, which is exactly what this adapter uses (raw secret on the token, KDF
/// in managed code), so the agreement tests run here. A P-256 key pair is generated on the token and
/// the derived keys are cross-checked against a BCL <see cref="ECDiffieHellman"/> peer.
/// </summary>
[Collection("SoftHsm")]
public sealed class ECDiffieHellmanPkcs11Tests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    // ASN.1 DER OID for the P-256 named curve (prime256v1 / secp256r1).
    private static readonly byte[] EcP256Oid = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    private Pkcs11Workspace OpenWorkspace() =>
        _backend.Library.OpenWorkspace(
            _backend.TokenLabel, CKU.CKU_USER, new SecurePin(_backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    private void RequireEcdh()
    {
        if (!_backend.Supports(CKM.CKM_ECDH1_DERIVE))
            throw new SkipTestException("Token does not implement CKM_ECDH1_DERIVE.");
    }

    // Generates a P-256 key pair on the token (private half CKA_DERIVE) and hands the adapter to the body.
    private void WithEcdh(Action<ECDiffieHellmanPkcs11> body)
    {
        RequireEcdh();
        using var workspace = OpenWorkspace();
        string label = $"ecdh-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .Label(label).Id(id).EcParams(EcP256Oid).Build();
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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void Ctor_NonEcKey_Throws()
    {
        using var workspace = OpenWorkspace();
        string label = $"ecdh-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
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

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKeyFromHash_AgreesWithBcl() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        byte[] aliceKey = alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA256);
        byte[] bobKey = bob.DeriveKeyFromHash(alice.PublicKey, HashAlgorithmName.SHA256);

        Assert.Equal(32, aliceKey.Length);
        Assert.Equal(bobKey, aliceKey);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKeyFromHash_WithPrependAppend_AgreesWithBcl() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] prepend = [1, 2, 3];
        byte[] append = [9, 8, 7, 6];

        byte[] aliceKey = alice.DeriveKeyFromHash(bob.PublicKey, HashAlgorithmName.SHA384, prepend, append);
        byte[] bobKey = bob.DeriveKeyFromHash(alice.PublicKey, HashAlgorithmName.SHA384, prepend, append);

        Assert.Equal(bobKey, aliceKey);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKeyFromHmac_AgreesWithBcl() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] hmacKey = [0xAA, 0xBB, 0xCC, 0xDD];

        byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);
        byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey, null, null);

        Assert.Equal(bobKey, aliceKey);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKeyFromHmac_NullKey_UsesSecret_AgreesWithBcl() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        byte[] aliceKey = alice.DeriveKeyFromHmac(bob.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);
        byte[] bobKey = bob.DeriveKeyFromHmac(alice.PublicKey, HashAlgorithmName.SHA256, hmacKey: null, null, null);

        Assert.Equal(bobKey, aliceKey);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveRawSecretAgreement_MatchesBcl() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        byte[] aliceZ = alice.DeriveRawSecretAgreement(bob.PublicKey);
        byte[] bobZ = bob.DeriveRawSecretAgreement(alice.PublicKey);

        Assert.Equal(32, aliceZ.Length);
        Assert.Equal(bobZ, aliceZ);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKeyMaterial_AgreesWithBcl() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        // DeriveKeyMaterial defaults to DeriveKeyFromHash with SHA-256.
        Assert.Equal(bob.DeriveKeyMaterial(alice.PublicKey), alice.DeriveKeyMaterial(bob.PublicKey));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void PublicKey_ExportsTokenPoint() => WithEcdh(alice =>
    {
        ECParameters fromExport = alice.ExportParameters(includePrivateParameters: false);
        ECParameters fromPublicKey = alice.PublicKey.ExportParameters();

        Assert.Equal(fromExport.Q.X, fromPublicKey.Q.X);
        Assert.Equal(fromExport.Q.Y, fromPublicKey.Q.Y);
        Assert.Equal(ECCurve.NamedCurves.nistP256.Oid.Value, fromPublicKey.Curve.Oid.Value);
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void DeriveKeyTls_NotSupported() => WithEcdh(alice =>
    {
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<NotSupportedException>(
            () => alice.DeriveKeyTls(bob.PublicKey, new byte[16], new byte[64]));
    });

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ExportParameters_Private_ThrowsInsecure() => WithEcdh(alice =>
        Assert.Throws<InsecureOperationException>(() => alice.ExportParameters(includePrivateParameters: true)));

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void ImportParameters_NotSupported() => WithEcdh(alice =>
        Assert.Throws<NotSupportedException>(() => alice.ImportParameters(new ECParameters())));
}
