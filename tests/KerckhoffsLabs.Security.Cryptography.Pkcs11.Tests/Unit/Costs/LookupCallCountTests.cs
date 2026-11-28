using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Costs;

/// <summary>
/// The native calls a lookup through <see cref="Pkcs11Session"/> costs on a token that reports the attributes PKCS#11
/// gives every object (<see cref="ManagedSoftToken.ReportsDefaultAttributes"/>): a search is
/// <c>C_FindObjectsInit</c>/<c>C_FindObjects</c>/<c>C_FindObjectsFinal</c>, and each object found is read with
/// <c>C_GetAttributeValue</c>.
/// </summary>
/// <remarks>
/// <para>
/// Where the reads come from:
/// </para>
/// <list type="bullet">
/// <item><description>The identity read of a found object takes two calls: its class, type and <c>CKA_PRIVATE</c> with
/// the lengths of its label and id, then the label and id at those lengths (one call when both are empty, as here: the
/// keys have a label and no id unless the test gives one, and the second call then reads only the label). See
/// <c>ObjectIdentityReader</c>.</description></item>
/// <item><description><see cref="Pkcs11Session.OpenKey(string)"/> refuses an ambiguous match, so it reads every
/// candidate (class, type, id, label, <c>CKA_PRIVATE</c>) with the generic two-call reader, pairs the halves, and builds
/// the key from what it read. A filter that names no class is searched once, without one, and matches that are not
/// keys are dropped by the class read, as <see cref="Pkcs11Session.FindKeys"/> does.</description></item>
/// <item><description><see cref="Pkcs11Session.OpenCertificate(string)"/> and
/// <see cref="Pkcs11Session.OpenObject(ObjectTemplate)"/> tell matches apart by count, so only the one match is
/// read, when it is built.</description></item>
/// </list>
/// <para>
/// <c>OpenKey</c> was 13 calls for a pair after #24 (three searches, every candidate read, a single key read twice);
/// it is now 7, as <c>FindKeys</c>. A change to a lookup's cost states its effect by updating these pins.
/// </para>
/// </remarks>
[Collection(FakeModuleCollection.Name)]
public sealed class LookupCallCountTests : IDisposable
{
    private const string PairLabel = "pair";
    private static readonly byte[] PairId = [0x0A, 0x0B];

    private readonly ManagedSoftToken _token = new() { ReportsDefaultAttributes = true };
    private readonly Pkcs11Library _library;
    private readonly Pkcs11Session _session;

    public LookupCallCountTests()
    {
        _library = _token.Load();
        _session = ManagedToken.OpenSession(_library);
    }

    public void Dispose()
    {
        _session.Dispose();
        _library.Dispose();
    }

    // === OpenKey ===========================================================

    // One search + 2 candidates × 2 generic reads; the key is built from the candidates.
    [Fact]
    public void OpenKey_ByLabel_OfAPair()
    {
        GeneratePair(PairLabel, PairId).Dispose();

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×4",
            NativeCalls.Of(_token, () => _session.OpenKey(PairLabel).Dispose()));
    }

    [Fact]
    public void OpenKey_ById_OfAPair()
    {
        GeneratePair(PairLabel, PairId).Dispose();

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×4",
            NativeCalls.Of(_token, () => _session.OpenKey(PairId).Dispose()));
    }

    // One search + the candidate's generic read (2): a single key is built from its candidate, not read again.
    [Fact]
    public void OpenKey_ByLabel_OfASecretKey()
    {
        _session.GenerateAesKey(256, "secret").Dispose();

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×2",
            NativeCalls.Of(_token, () => _session.OpenKey("secret").Dispose()));
    }

    [Fact]
    public void OpenKey_ByLabel_OfAPrivateKeyWithoutItsPublicHalf()
    {
        using (Pkcs11Key pair = GeneratePair("lone", [0x0C]))
            _session.Core.DestroyObject(pair.PublicHandle);

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×2",
            NativeCalls.Of(_token, () => _session.OpenKey("lone").Dispose()));
    }

    // A filter that names the class searches that class: one search + the candidate (2).
    [Fact]
    public void OpenKey_ByAFilterThatNamesTheClass()
    {
        GeneratePair(PairLabel, PairId).Dispose();
        using ObjectTemplate filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY).Label(PairLabel).Build();

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×2",
            NativeCalls.Of(_token, () => _session.OpenKey(filter).Dispose()));
    }

    // === FindKeys ==========================================================

    // One search, then the identity read of each key found: 3 + 2 per key, the label and id read in one call.
    [Fact]
    public void FindKeys_ByLabel_OfAPair()
    {
        GeneratePair(PairLabel, PairId).Dispose();
        using ObjectTemplate filter = ObjectTemplate.Empty().Label(PairLabel).Build();

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×4",
            NativeCalls.Of(_token, () => _session.FindKeys(filter).Dispose()));
    }

    // The cost is linear in the keys found: 3 + 2N, with no search per key (CP-008 resolves companions lazily).
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public void FindKeys_CostsTwoReadsPerKey(int keys)
    {
        for (int i = 0; i < keys; i++)
            _session.GenerateAesKey(256, "many").Dispose();
        using ObjectTemplate filter = ObjectTemplate.Empty().Label("many").Build();

        string calls = NativeCalls.Of(_token, () =>
        {
            using ReadOnlyDisposableList<Pkcs11Key> found = _session.FindKeys(filter);
            Assert.Equal(keys, found.Count);
        });

        Assert.Equal($"C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×{2 * keys}", calls);
    }

    // A key found by its private half looks its public half up on the first use that needs it, once: a search by id
    // and type (3) and one CKA_PRIVATE read of the half found, which ties a private one to the login (1). The
    // verification itself adds the key-strength read of the public half (2, see KeyOperationCallCountTests) and its
    // own two calls; the next one pays only those.
    [Fact]
    public void FindKeys_ThenVerify_LooksThePublicHalfUpOnce()
    {
        GeneratePair(PairLabel, PairId).Dispose();
        using ObjectTemplate filter = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY).Label(PairLabel).Build();
        using ReadOnlyDisposableList<Pkcs11Key> keys = _session.FindKeys(filter);
        Pkcs11Key key = Assert.Single(keys);
        var ecdsa = new Mechanism(CKM.CKM_ECDSA_SHA256);
        byte[] signature = key.Sign(ecdsa, new byte[32]);

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×3, C_Verify×1, C_VerifyInit×1",
            NativeCalls.Of(_token, () => Assert.True(key.Verify(ecdsa, new byte[32], signature))));
        Assert.Equal("C_GetAttributeValue×2, C_Verify×1, C_VerifyInit×1",
            NativeCalls.Of(_token, () => Assert.True(key.Verify(ecdsa, new byte[32], signature))));
    }

    // === OpenCertificate / OpenObject ======================================

    // One search + the certificate's read of its value, label, id and CKA_PRIVATE (2).
    [Fact]
    public void OpenCertificate_ByLabel()
    {
        using (X509Certificate2 certificate = SelfSigned())
            _session.ImportCertificate(certificate, "cert", [0x0D]).Dispose();

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×2",
            NativeCalls.Of(_token, () => _session.OpenCertificate("cert").Dispose()));
    }

    // One search + the identity read of the match, which falls back to the generic reader (3): a data object has no
    // CKA_ID, so the module answers CKR_ATTRIBUTE_TYPE_INVALID for it, as a token does.
    [Fact]
    public void OpenObject_ByLabel_OfADataObject()
    {
        using (ObjectTemplate data = ObjectTemplate.ForData().Label("blob").Value([0x01, 0x02, 0x03]).Build())
            _session.CreateObject(data).Dispose();
        using ObjectTemplate filter = ObjectTemplate.ForData().Label("blob").Build();

        Assert.Equal("C_FindObjects×1, C_FindObjectsFinal×1, C_FindObjectsInit×1, C_GetAttributeValue×3",
            NativeCalls.Of(_token, () => _session.OpenObject(filter).Dispose()));
    }

    // === Helpers ===========================================================

    private Pkcs11Key GeneratePair(string label, byte[] id)
    {
        using ObjectTemplate publicKey = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
            .EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Verify().Label(label).Id(id).Build();
        using ObjectTemplate privateKey = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Sign().Label(label).Id(id).Build();
        return _session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), publicKey, privateKey);
    }

    private static X509Certificate2 SelfSigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=lookup", key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
