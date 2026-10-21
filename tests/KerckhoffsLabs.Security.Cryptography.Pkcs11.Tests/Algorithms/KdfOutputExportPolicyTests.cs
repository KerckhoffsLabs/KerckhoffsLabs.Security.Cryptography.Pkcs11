using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Algorithms;

/// <summary>
/// The byte-returning KDF overloads read the derived secret off the token. A policy may accept the
/// extractable, non-sensitive key those overloads derive and still refuse plaintext KDF output (a
/// FIPS-style posture), so the export check has to be asked on its own, before anything is derived:
/// under the default policy the key template is refused too, which would hide a missing export check.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KdfOutputExportPolicyTests
{
    // Refuses reading key material off the token and allows everything else.
    private sealed class NoExportPolicy : ICryptoPolicy
    {
        public List<PolicyRequest> Seen { get; } = [];
        public string Name => "NoExport";
        public bool AllowsOverride => false;
        public PolicyDecision Evaluate(PolicyRequest request)
        {
            Seen.Add(request);
            return request is KeyMaterialExportRequest ? PolicyDecision.Deny("no export") : PolicyDecision.Allow;
        }
    }

    private static readonly HashAlgorithmName Sha256 = HashAlgorithmName.SHA256;

    private static readonly Dictionary<string, Action<Pkcs11Key>> ByteResults = new()
    {
        ["HKDF DeriveKey"] = k => HkdfPkcs11.DeriveKey(Sha256, k, 32),
        ["HKDF DeriveKey(span)"] = k => HkdfPkcs11.DeriveKey(Sha256, k, new byte[32], [], []),
        ["HKDF Extract"] = k => HkdfPkcs11.Extract(Sha256, k),
        ["HKDF Extract(span)"] = k => HkdfPkcs11.Extract(Sha256, k, [], new byte[32]),
        ["HKDF Expand"] = k => HkdfPkcs11.Expand(Sha256, k, 32),
        ["HKDF Expand(span)"] = k => HkdfPkcs11.Expand(Sha256, k, new byte[32], []),
        ["SP800-108 DeriveKey"] = k => { using var kdf = new SP800108HmacCounterKdfPkcs11(k, Sha256); kdf.DeriveKey([1], [2], 32); },
        ["SP800-108 DeriveKey(span)"] = k => { using var kdf = new SP800108HmacCounterKdfPkcs11(k, Sha256); kdf.DeriveKey([1], [2], new byte[32]); },
    };

    public static TheoryData<string> ByteResultNames() => [.. ByteResults.Keys];

    [Theory]
    [MemberData(nameof(ByteResultNames))]
    public void ByteResult_IsRefusedByTheExportCheck_BeforeAnythingIsDerived(string call)
    {
        var policy = new NoExportPolicy();
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, policy);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(new byte[32]).Derive().Build();
        using var key = session.ImportKey(tpl);
        policy.Seen.Clear();

        var e = Assert.Throws<CryptoPolicyViolationException>(() => ByteResults[call](key));

        Assert.Equal(KeyMaterialExportKind.KdfOutput, Assert.IsType<KeyMaterialExportRequest>(e.Request).Kind);
        Assert.Empty(policy.Seen.OfType<KeyTemplateRequest>());
        Assert.Empty(policy.Seen.OfType<MechanismUseRequest>());
    }
}
