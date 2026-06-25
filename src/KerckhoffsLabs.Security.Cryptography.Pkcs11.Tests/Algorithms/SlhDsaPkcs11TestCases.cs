using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

// SlhDsa (FIPS 205) and ExportPkcs8PrivateKey are evaluation-only BCL APIs (SYSLIB5006). We invoke
// them deliberately to assert our adapter's behaviour; suppress the experimental diagnostic.
#pragma warning disable SYSLIB5006

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// Backend-agnostic SlhDsaPkcs11 (FIPS 205) tests: sign/verify across parameter sets and with context,
/// and key-material export (public encoding; private export refused). The non-SLH-DSA-key constructor
/// check runs anywhere; the real-crypto cases skip where the backend cannot operate SLH-DSA
/// (<see cref="IPkcs11Backend.SupportsSlhDsa"/>) — no shipping software token implements it today.
/// </summary>
internal static class SlhDsaPkcs11TestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) =>
        backend.Library.OpenWorkspace(backend.TokenLabel, CKU.CKU_USER, new SecurePin(backend.UserPin.Span));

    private static void DestroyByLabel(Pkcs11Workspace workspace, string label)
    {
        using var filter = ObjectTemplate.Empty().Label(label).Build();
        foreach (var k in workspace.FindKeys(filter))
        {
            k.Delete();
            k.Dispose();
        }
    }

    // Generates an SLH-DSA key pair for the parameter set, wraps it as SlhDsaPkcs11, runs the body,
    // then destroys both handles. Skips where the backend cannot operate SLH-DSA. CKA_PARAMETER_SET
    // goes on the public template.
    private static void WithSlhDsa(IPkcs11Backend backend, CkpSlhDsa parameterSet, Action<SlhDsaPkcs11> body)
    {
        if (!backend.SupportsSlhDsa)
            throw new SkipTestException("Backend cannot operate SLH-DSA (CKM_SLH_DSA unavailable).");

        using var workspace = OpenWorkspace(backend);
        string label = $"slhdsa-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_SLH_DSA)
            .Label(label).Id(id).Verify()
            .Attribute(CKA.CKA_PARAMETER_SET, (ulong)parameterSet).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_SLH_DSA)
            .Label(label).Id(id).Sign().Build();

        var key = workspace.GenerateKey(new Mechanism(CKM.CKM_SLH_DSA_KEY_PAIR_GEN), privTpl, pubTpl);
        try
        {
            using var slhdsa = new SlhDsaPkcs11(key);
            body(slhdsa);
        }
        finally
        {
            try { key.Delete(); } catch { /* best-effort cleanup */ }
            key.Dispose();
        }
    }

    internal static void Assert_Ctor_NonSlhDsaKey_Throws(IPkcs11Backend backend)
    {
        using var workspace = OpenWorkspace(backend);
        string label = $"slhdsa-wrongtype-{Guid.NewGuid():N}";
        using (var t = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build())
        {
            using var _ = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), t);
        }
        try
        {
            using var key = workspace.OpenKey(label);
            var ex = Assert.Throws<ArgumentException>(() => new SlhDsaPkcs11(key));
            Assert.Equal("key", ex.ParamName);
        }
        finally { DestroyByLabel(workspace, label); }
    }

    internal static void Assert_SignVerifyData_RoundTrips(IPkcs11Backend backend, CkpSlhDsa parameterSet) =>
        WithSlhDsa(backend, parameterSet, slhdsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("slh-dsa round trip");
            byte[] sig = slhdsa.SignData(data);
            Assert.Equal(slhdsa.Algorithm.SignatureSizeInBytes, sig.Length);
            Assert.True(slhdsa.VerifyData(data, sig));

            byte[] tampered = [.. data];
            tampered[0] ^= 0xFF;
            Assert.False(slhdsa.VerifyData(tampered, sig));
        });

    internal static void Assert_SignVerifyData_WithContext_RoundTrips(IPkcs11Backend backend) =>
        WithSlhDsa(backend, CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        {
            byte[] data = Encoding.UTF8.GetBytes("context-bound message");
            byte[] context = Encoding.UTF8.GetBytes("app-context");

            byte[] sig = slhdsa.SignData(data, context);
            Assert.True(slhdsa.VerifyData(data, sig, context));
            // A signature made with a context must not verify without it.
            Assert.False(slhdsa.VerifyData(data, sig));
        });

    internal static void Assert_SignData_ContextTooLong_Throws(IPkcs11Backend backend) =>
        WithSlhDsa(backend, CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            // The BCL validates the >255-byte context first (ArgumentOutOfRangeException) before our own
            // ArgumentException would fire; both derive from ArgumentException.
            Assert.ThrowsAny<ArgumentException>(() => slhdsa.SignData(new byte[4], new byte[256])));

    internal static void Assert_ExportSlhDsaPublicKey_ReturnsStandardEncoding(IPkcs11Backend backend) =>
        WithSlhDsa(backend, CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
        {
            byte[] pub = slhdsa.ExportSlhDsaPublicKey();
            Assert.Equal(slhdsa.Algorithm.PublicKeySizeInBytes, pub.Length);
        });

    internal static void Assert_ExportSlhDsaPrivateKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithSlhDsa(backend, CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            Assert.Throws<InsecureOperationException>(() => slhdsa.ExportSlhDsaPrivateKey()));

    internal static void Assert_ExportPkcs8PrivateKey_ThrowsInsecure(IPkcs11Backend backend) =>
        WithSlhDsa(backend, CkpSlhDsa.CKP_SLH_DSA_SHA2_128F, slhdsa =>
            Assert.Throws<InsecureOperationException>(() => slhdsa.ExportPkcs8PrivateKey()));
}
