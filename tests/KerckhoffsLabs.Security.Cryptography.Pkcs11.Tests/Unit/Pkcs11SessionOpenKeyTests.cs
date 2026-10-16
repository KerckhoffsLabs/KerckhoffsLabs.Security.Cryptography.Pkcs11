using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Session.OpenKey(string)"/> and its siblings must identify exactly one key:
/// only key objects match, a pair counts as one key, and several keys are refused rather than resolved
/// by picking one. Runs on the in-process token, where duplicate labels are easy to set up.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionOpenKeyTests : IDisposable
{
    private const string Label = "shared-label";
    private static readonly byte[] PairId = [0x0A, 0x0B];

    private readonly Pkcs11Library _library = ManagedToken.NewLibrary();
    private readonly Pkcs11Session _session;

    public Pkcs11SessionOpenKeyTests() => _session = ManagedToken.OpenSession(_library);

    public void Dispose()
    {
        _session.Dispose();
        _library.Dispose();
    }

    private void AddAesKey(string label, byte[]? id = null)
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).Value(new byte[32]).Encrypt().Decrypt();
        if (id is not null) builder = builder.Id(id);
        using var template = builder.Build();
        using var _ = _session.ImportKey(template);
    }

    private void AddEcPair(string label, byte[]? id = null)
    {
        var pub = ObjectTemplate.ForPublicKey(CKK.CKK_EC).EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Verify().Label(label);
        var priv = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Sign().Label(label);
        if (id is not null)
        {
            pub = pub.Id(id);
            priv = priv.Id(id);
        }
        using var pubTemplate = pub.Build();
        using var privTemplate = priv.Build();
        using var _ = _session.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTemplate, privTemplate);
    }

    private static ObjectTemplate Filter(string label, CKO? objectClass = null, CKK? keyType = null)
    {
        var builder = ObjectTemplate.Empty().Label(label);
        if (objectClass is { } c) builder = builder.Attribute(CKA.CKA_CLASS, (ulong)c);
        if (keyType is { } t) builder = builder.Attribute(CKA.CKA_KEY_TYPE, (ulong)t);
        return builder.Build();
    }

    private void AddDataObject(string label)
    {
        using var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_DATA)
            .Label(label)
            .Build();
        _session.Core.CreateObject([.. template.Attributes]);
    }

    // === One key =============================================================

    [Fact]
    public void KeyPairSharingTheLabel_IsOneKey_WithBothHalves()
    {
        AddEcPair(Label, PairId);

        using Pkcs11Key key = _session.OpenKey(Label);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    [Fact]
    public void KeyPairWithNoId_IsOneKey_WithBothHalves()
    {
        AddEcPair(Label);

        using Pkcs11Key key = _session.OpenKey(Label);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    [Fact]
    public void NonKeyObjectSharingTheLabel_IsIgnored()
    {
        AddAesKey(Label);
        AddDataObject(Label);

        using Pkcs11Key key = _session.OpenKey(Label);

        Assert.Equal(CKK.CKK_AES, key.KeyType);
    }

    [Fact]
    public void ClassFilter_MatchingOneHalf_StillAttachesTheOther()
    {
        AddEcPair(Label, PairId);

        using ObjectTemplate filter = Filter(Label, CKO.CKO_PUBLIC_KEY);
        using Pkcs11Key key = _session.OpenKey(filter);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    [Fact]
    public void OpenById_FindsThePair()
    {
        AddEcPair(Label, PairId);

        using Pkcs11Key key = _session.OpenKey(PairId);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    // === Ambiguity ===========================================================

    [Fact]
    public void TwoSecretKeysSharingTheLabel_AreRefused()
    {
        AddAesKey(Label);
        AddAesKey(Label);

        var ex = Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenKey(Label));

        Assert.Equal(CKR.CKR_OK, ex.ReturnValue);
        Assert.Equal("C_FindObjects", ex.Method);
        Assert.IsAssignableFrom<Pkcs11ObjectException>(ex);
    }

    [Fact]
    public void TwoPairsSharingTheIdButNotTheKeyType_AreRefused()
    {
        AddEcPair(Label, PairId);
        AddAesKey(Label, PairId);

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenKey(PairId));
    }

    [Fact]
    public void TwoPrivateKeysSharingIdAndType_AreRefused()
    {
        AddEcPair(Label, PairId);
        AddEcPair(Label, PairId);

        using ObjectTemplate filter = ObjectTemplate.Empty().Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_PRIVATE_KEY).Id(PairId).Build();
        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenKey(filter));
    }

    [Fact]
    public void ClassFilter_ResolvesAnAmbiguousLabel()
    {
        AddEcPair(Label, PairId);
        AddAesKey(Label);

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenKey(Label));

        using ObjectTemplate secretFilter = Filter(Label, CKO.CKO_SECRET_KEY);
        using Pkcs11Key secret = _session.OpenKey(secretFilter);
        Assert.Equal(CKK.CKK_AES, secret.KeyType);

        using ObjectTemplate privateFilter = Filter(Label, CKO.CKO_PRIVATE_KEY);
        using Pkcs11Key pair = _session.OpenKey(privateFilter);
        Assert.Equal(CKK.CKK_EC, pair.KeyType);
        Assert.NotEqual(ObjectHandle.Invalid, pair.PublicHandle);
    }

    // A key class can't tell two pairs apart; a key type can.
    [Fact]
    public void KeyTypeFilter_ResolvesTwoPairsSharingTheLabel()
    {
        AddEcPair(Label, PairId);
        using (_session.GenerateRsaSigningKeyPair(3072, Label)) { }

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenKey(Label));
        using ObjectTemplate privateOnly = Filter(Label, CKO.CKO_PRIVATE_KEY);
        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.OpenKey(privateOnly));

        using ObjectTemplate ecFilter = Filter(Label, keyType: CKK.CKK_EC);
        using Pkcs11Key ec = _session.OpenKey(ecFilter);
        Assert.Equal(CKK.CKK_EC, ec.KeyType);

        using ObjectTemplate rsaFilter = Filter(Label, keyType: CKK.CKK_RSA);
        Assert.True(_session.TryOpenKey(rsaFilter, out Pkcs11Key? rsa));
        using (rsa)
            Assert.Equal(CKK.CKK_RSA, rsa.KeyType);
    }

    [Fact]
    public void TryOpenKey_StillThrowsOnAmbiguity()
    {
        AddAesKey(Label);
        AddAesKey(Label);

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _session.TryOpenKey(Label, out _));
    }

    // === No key ==============================================================

    [Fact]
    public void NoMatch_OpenKeyThrowsNotFound_AndTryOpenKeyReturnsFalse()
    {
        AddDataObject(Label);

        var ex = Assert.Throws<Pkcs11ObjectNotFoundException>(() => _session.OpenKey(Label));
        Assert.Equal(CKR.CKR_OK, ex.ReturnValue);
        Assert.Contains(Label, ex.Message);
        Assert.IsAssignableFrom<Pkcs11ObjectException>(ex);
        Assert.Throws<Pkcs11ObjectNotFoundException>(() => _session.OpenKey(PairId));
        using ObjectTemplate filter = Filter(Label);
        Assert.Throws<Pkcs11ObjectNotFoundException>(() => _session.OpenKey(filter));
        Assert.False(_session.TryOpenKey(Label, out Pkcs11Key? byLabel));
        Assert.Null(byLabel);
        Assert.False(_session.TryOpenKey(PairId, out Pkcs11Key? byId));
        Assert.Null(byId);
    }

    [Fact]
    public void ClassFilter_ExcludingTheOnlyMatch_IsNotFound()
    {
        AddAesKey(Label);

        using ObjectTemplate filter = Filter(Label, CKO.CKO_PRIVATE_KEY);
        Assert.False(_session.TryOpenKey(filter, out _));
    }

    // === Arguments ===========================================================

    [Theory]
    [InlineData(CKO.CKO_CERTIFICATE)]
    [InlineData(CKO.CKO_DATA)]
    public void FilterNamingANonKeyClass_IsRejected(CKO objectClass)
    {
        using ObjectTemplate filter = Filter(Label, objectClass);

        var ex = Assert.Throws<ArgumentException>(() => _session.OpenKey(filter));
        Assert.Equal("filter", ex.ParamName);
    }


    [Fact]
    public void InvalidArguments_AreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => _session.OpenKey((string)null!));
        Assert.Throws<ArgumentNullException>(() => _session.OpenKey((ObjectTemplate)null!));
        Assert.Throws<ArgumentNullException>(() => _session.TryOpenKey((ObjectTemplate)null!, out _));
        Assert.Throws<ArgumentException>(() => _session.OpenKey(ReadOnlySpan<byte>.Empty));
        Assert.Throws<ArgumentException>(() => _session.TryOpenKey(ReadOnlySpan<byte>.Empty, out _));
    }
}
