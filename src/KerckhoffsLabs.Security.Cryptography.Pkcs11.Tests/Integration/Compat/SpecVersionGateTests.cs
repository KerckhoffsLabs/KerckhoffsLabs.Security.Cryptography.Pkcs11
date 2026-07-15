using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// End-to-end spec-version compatibility over the pkcs11-gate shims (the real-module
/// half): the same managed API surface must negotiate correctly against a v2.40-only module
/// and a v3.0-but-not-v3.2 module, degrade the unavailable functions to clean
/// <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> failures, and route crypto through the
/// correct per-version code path — all against real SoftHSM crypto behind the gate.
/// </summary>
internal static class SpecVersionGateTestSupport
{
    internal static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    /// <summary>AES-GCM round-trip + tamper rejection through <see cref="AesGcmPkcs11"/>.</summary>
    internal static void AssertAesGcmRoundTrips(Pkcs11Workspace workspace)
    {
        using var key = workspace.GenerateAesKey(256);
        using var gcm = new AesGcmPkcs11(key);

        byte[] nonce = workspace.GenerateRandom(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("spec-version gate round trip");
        byte[] aad = Encoding.UTF8.GetBytes("gate-aad");
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        Assert.NotEqual(plaintext, ciphertext);

        byte[] decrypted = new byte[plaintext.Length];
        gcm.Decrypt(nonce, ciphertext, tag, decrypted, aad);
        Assert.Equal(plaintext, decrypted);

        byte[] tamperedTag = [.. tag];
        tamperedTag[0] ^= 0xFF;
        Assert.ThrowsAny<Pkcs11Exception>(() => gcm.Decrypt(nonce, ciphertext, tamperedTag, new byte[plaintext.Length], aad));
    }

    /// <summary>SHA-256 through the token must match the BCL over the same input.</summary>
    internal static void AssertSha256MatchesBcl(Pkcs11Workspace workspace)
    {
        byte[] data = Encoding.UTF8.GetBytes("spec-version gate digest");
        using var sha = new SHA256Pkcs11(workspace);
        Assert.Equal(SHA256.HashData(data), sha.ComputeHash(data));
    }

    /// <summary>RSA-PSS sign/verify round-trip through <see cref="RSAPkcs11"/>.</summary>
    internal static void AssertRsaSignVerifyRoundTrips(Pkcs11Workspace workspace)
    {
        using var key = workspace.GenerateRsaKeyPair(2048);
        using var rsa = new RSAPkcs11(key);

        byte[] data = Encoding.UTF8.GetBytes("spec-version gate signature");
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.True(rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));

        byte[] tampered = [.. data];
        tampered[0] ^= 0xFF;
        Assert.False(rsa.VerifyData(tampered, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }
}

/// <summary>The wrapper against a v2.40-only module (gate 2.40 over SoftHSM).</summary>
[Collection("SoftHsm")]
public sealed class SpecVersionGateTests_V240(SoftHsmGate240Fixture backend)
{
    private readonly SoftHsmGate240Fixture _backend = backend;
    public static bool Available => SoftHsmGate240Fixture.Available;

    [ConditionalFact(nameof(Available))]
    public void Negotiation_ReportsV240OnlySurface()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        Assert.False(ws.Session.SupportsMessageApi);
        Assert.False(ws.Session.SupportsV32Api);
    }

    [ConditionalFact(nameof(Available))]
    public void GetInterfaces_Throws_FunctionNotSupported()
    {
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => _backend.Library.GetInterfaces());
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [ConditionalFact(nameof(Available))]
    public void LoginUser_Throws_FunctionNotSupported()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        using var pin = new SecurePin(_backend.UserPin.Span);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => ws.Session.LoginUser(CKU.CKU_USER, pin, "user"));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [ConditionalFact(nameof(Available))]
    public void CancelOperations_Throws_FunctionNotSupported()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => ws.Session.CancelOperations((ulong)CKF.CKF_ENCRYPT));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    // A v3.2 call on a v2.40 module must surface the documented
    // CKR through the real null-function-pointer dispatch guard — never an NRE.
    [ConditionalFact(nameof(Available))]
    public void EncapsulateKey_Throws_FunctionNotSupported()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        using var mech = new Mechanism(CKM.CKM_ML_KEM);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => ws.Session.EncapsulateKey(mech, new Internal.ObjectHandle(1), []));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    // The load-bearing crypto case: with the message API absent, AesGcmPkcs11 must take the
    // v2.40 single-part fallback (ciphertext‖tag concatenation) — a path no v3.x CI backend
    // exercises against real crypto.
    [ConditionalFact(nameof(Available))]
    public void AesGcm_RoundTrips_ViaV240ConcatFallback()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        Assert.False(ws.Session.SupportsMessageApi); // proves the fallback path is the one taken
        SpecVersionGateTestSupport.AssertAesGcmRoundTrips(ws);
    }

    [ConditionalFact(nameof(Available))]
    public void Sha256_MatchesBcl()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        SpecVersionGateTestSupport.AssertSha256MatchesBcl(ws);
    }

    [ConditionalFact(nameof(Available))]
    public void RsaPss_SignVerify_RoundTrips()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        SpecVersionGateTestSupport.AssertRsaSignVerifyRoundTrips(ws);
    }
}

/// <summary>The wrapper against a v3.0-but-not-v3.2 module (gate 3.0 over SoftHSM).</summary>
[Collection("SoftHsm")]
public sealed class SpecVersionGateTests_V30(SoftHsmGate30Fixture backend)
{
    private readonly SoftHsmGate30Fixture _backend = backend;
    public static bool Available => SoftHsmGate30Fixture.Available;

    [ConditionalFact(nameof(Available))]
    public void Negotiation_ReportsV30Surface_WithoutV32()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        // The gate rewrote the interface version to {3,0}: message API bound, v3.2 additions not.
        Assert.True(ws.Session.SupportsMessageApi);
        Assert.False(ws.Session.SupportsV32Api);
    }

    // The same v3.2 degradation contract holds on the v3.0 tier.
    [ConditionalFact(nameof(Available))]
    public void EncapsulateKey_Throws_FunctionNotSupported()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        using var mech = new Mechanism(CKM.CKM_ML_KEM);
        var ex = Assert.ThrowsAny<Pkcs11Exception>(
            () => ws.Session.EncapsulateKey(mech, new Internal.ObjectHandle(1), []));
        Assert.Equal(CKR.CKR_FUNCTION_NOT_SUPPORTED, ex.ReturnValue);
    }

    [ConditionalFact(nameof(Available))]
    public void GetInterfaces_Succeeds()
    {
        // C_GetInterfaceList is bound from the (v3.0-truncated) interface table and reaches the
        // real module, so interface enumeration works on a v3.0 module.
        var interfaces = _backend.Library.GetInterfaces();
        Assert.NotEmpty(interfaces);
        Assert.Contains(interfaces, i => i.Name == "PKCS 11");
    }

    [ConditionalFact(nameof(Available))]
    public void AesGcm_RoundTrips()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        Assert.True(ws.Session.SupportsMessageApi);
        SpecVersionGateTestSupport.AssertAesGcmRoundTrips(ws);
    }

    [ConditionalFact(nameof(Available))]
    public void Sha256_MatchesBcl()
    {
        using var ws = SpecVersionGateTestSupport.OpenWorkspace(_backend);
        SpecVersionGateTestSupport.AssertSha256MatchesBcl(ws);
    }
}
