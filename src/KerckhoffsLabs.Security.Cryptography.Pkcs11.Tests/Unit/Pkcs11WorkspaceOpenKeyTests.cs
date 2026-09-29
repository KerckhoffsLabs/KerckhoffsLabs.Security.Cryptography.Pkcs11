using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Workspace.OpenKey(string, CKO?)"/> and its siblings must identify exactly one key:
/// only key objects match, a pair counts as one key, and several keys are refused rather than resolved
/// by picking one. Runs on the in-process token, where duplicate labels are easy to set up.
/// </summary>
public sealed class Pkcs11WorkspaceOpenKeyTests : IDisposable
{
    private const string Label = "shared-label";
    private static readonly byte[] PairId = [0x0A, 0x0B];

    private readonly Pkcs11Library _library = ManagedToken.NewLibrary();
    private readonly Pkcs11Workspace _workspace;

    public Pkcs11WorkspaceOpenKeyTests() => _workspace = ManagedToken.OpenWorkspace(_library);

    public void Dispose()
    {
        _workspace.Dispose();
        _library.Dispose();
    }

    private void AddAesKey(string label, byte[]? id = null)
    {
        var builder = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).Value(new byte[32]).Encrypt().Decrypt();
        if (id is not null) builder = builder.Id(id);
        using var template = builder.Build();
        using var _ = _workspace.ImportKey(template);
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
        using var _ = _workspace.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTemplate, privTemplate);
    }

    private void AddDataObject(string label)
    {
        using var template = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_DATA)
            .Label(label)
            .Build();
        _workspace.Session.CreateObject([.. template.Attributes]);
    }

    // === One key =============================================================

    [Fact]
    public void KeyPairSharingTheLabel_IsOneKey_WithBothHalves()
    {
        AddEcPair(Label, PairId);

        using Pkcs11Key key = _workspace.OpenKey(Label);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    [Fact]
    public void KeyPairWithNoId_IsOneKey_WithBothHalves()
    {
        AddEcPair(Label);

        using Pkcs11Key key = _workspace.OpenKey(Label);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    [Fact]
    public void NonKeyObjectSharingTheLabel_IsIgnored()
    {
        AddAesKey(Label);
        AddDataObject(Label);

        using Pkcs11Key key = _workspace.OpenKey(Label);

        Assert.Equal(CKK.CKK_AES, key.KeyType);
    }

    [Fact]
    public void KeyClassFilter_MatchingOneHalf_StillAttachesTheOther()
    {
        AddEcPair(Label, PairId);

        using Pkcs11Key key = _workspace.OpenKey(Label, CKO.CKO_PUBLIC_KEY);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    [Fact]
    public void OpenById_FindsThePair()
    {
        AddEcPair(Label, PairId);

        using Pkcs11Key key = _workspace.OpenKey(PairId);

        Assert.NotEqual(ObjectHandle.Invalid, key.PrivateHandle);
        Assert.NotEqual(ObjectHandle.Invalid, key.PublicHandle);
    }

    // === Ambiguity ===========================================================

    [Fact]
    public void TwoSecretKeysSharingTheLabel_AreRefused()
    {
        AddAesKey(Label);
        AddAesKey(Label);

        var ex = Assert.Throws<Pkcs11AmbiguousObjectException>(() => _workspace.OpenKey(Label));

        Assert.Equal(CKR.CKR_OK, ex.ReturnValue);
        Assert.Equal("C_FindObjects", ex.Method);
        Assert.IsAssignableFrom<Pkcs11ObjectException>(ex);
    }

    [Fact]
    public void TwoPairsSharingTheIdButNotTheKeyType_AreRefused()
    {
        AddEcPair(Label, PairId);
        AddAesKey(Label, PairId);

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _workspace.OpenKey(PairId));
    }

    [Fact]
    public void TwoPrivateKeysSharingIdAndType_AreRefused()
    {
        AddEcPair(Label, PairId);
        AddEcPair(Label, PairId);

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _workspace.OpenKey(PairId, CKO.CKO_PRIVATE_KEY));
    }

    [Fact]
    public void KeyClassFilter_ResolvesAnAmbiguousLabel()
    {
        AddEcPair(Label, PairId);
        AddAesKey(Label);

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _workspace.OpenKey(Label));

        using Pkcs11Key secret = _workspace.OpenKey(Label, CKO.CKO_SECRET_KEY);
        Assert.Equal(CKK.CKK_AES, secret.KeyType);

        using Pkcs11Key pair = _workspace.OpenKey(Label, CKO.CKO_PRIVATE_KEY);
        Assert.Equal(CKK.CKK_EC, pair.KeyType);
        Assert.NotEqual(ObjectHandle.Invalid, pair.PublicHandle);
    }

    [Fact]
    public void TryOpenKey_StillThrowsOnAmbiguity()
    {
        AddAesKey(Label);
        AddAesKey(Label);

        Assert.Throws<Pkcs11AmbiguousObjectException>(() => _workspace.TryOpenKey(Label, out _));
    }

    // === No key ==============================================================

    [Fact]
    public void NoMatch_OpenKeyThrowsKeyNotFound_AndTryOpenKeyReturnsFalse()
    {
        AddDataObject(Label);

        Assert.Throws<KeyNotFoundException>(() => _workspace.OpenKey(Label));
        Assert.Throws<KeyNotFoundException>(() => _workspace.OpenKey(PairId));
        Assert.False(_workspace.TryOpenKey(Label, out Pkcs11Key? byLabel));
        Assert.Null(byLabel);
        Assert.False(_workspace.TryOpenKey(PairId, out Pkcs11Key? byId));
        Assert.Null(byId);
    }

    [Fact]
    public void KeyClassFilter_ExcludingTheOnlyMatch_IsNotFound()
    {
        AddAesKey(Label);

        Assert.False(_workspace.TryOpenKey(Label, out _, CKO.CKO_PRIVATE_KEY));
    }

    // === Arguments ===========================================================

    [Theory]
    [InlineData(CKO.CKO_CERTIFICATE)]
    [InlineData(CKO.CKO_DATA)]
    public void NonKeyClass_IsRejected(CKO keyClass)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => _workspace.OpenKey(Label, keyClass));
        Assert.Equal("keyClass", ex.ParamName);
    }

    [Fact]
    public void InvalidArguments_AreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => _workspace.OpenKey((string)null!));
        Assert.Throws<ArgumentException>(() => _workspace.OpenKey(ReadOnlySpan<byte>.Empty));
        Assert.Throws<ArgumentException>(() => _workspace.TryOpenKey(ReadOnlySpan<byte>.Empty, out _));
    }
}
