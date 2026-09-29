using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Workspace.GenerateKeyPair"/> takes its templates in <c>C_GenerateKeyPair</c>
/// order — public, then private — and refuses a template whose <c>CKA_CLASS</c> names the other
/// half, since two <see cref="ObjectTemplate"/> arguments swap without a compile error.
/// </summary>
public sealed class Pkcs11WorkspaceGenerateKeyPairTests
{
    private static ObjectTemplate PublicTemplate() => ObjectTemplate.ForPublicKey(CKK.CKK_EC)
        .Label("pair").Verify().EcParams(Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams()).Build();

    private static ObjectTemplate PrivateTemplate() => ObjectTemplate.ForPrivateKey(CKK.CKK_EC)
        .Label("pair").Sign().Build();

    [Fact]
    public void SpecOrder_GeneratesAPairCarryingBothHandles()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var pubTpl = PublicTemplate();
        using var privTpl = PrivateTemplate();

        using var key = workspace.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, privTpl);

        Assert.Equal(CKK.CKK_EC, key.KeyType);
        Assert.False(key.PublicHandle.IsInvalid);
        Assert.False(key.PrivateHandle.IsInvalid);
    }

    [Fact]
    public void SwappedTemplates_AreRefusedBeforeTheToken()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var pubTpl = PublicTemplate();
        using var privTpl = PrivateTemplate();

        var ex = Assert.Throws<ArgumentException>(() =>
            workspace.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl));
        Assert.Equal("publicKeyTemplate", ex.ParamName);
    }

    [Fact]
    public void PublicTemplateInThePrivatePosition_IsRefused()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var pubTpl = PublicTemplate();
        using var secondPubTpl = PublicTemplate();

        var ex = Assert.Throws<ArgumentException>(() =>
            workspace.GenerateKeyPair(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), pubTpl, secondPubTpl));
        Assert.Equal("privateKeyTemplate", ex.ParamName);
    }
}
