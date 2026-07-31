using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Every path that creates a token object refuses a deliberately weakened template unless the
/// workspace has opted in.
/// </summary>
/// <remarks>
/// <para>
/// The policy is only worth anything if it holds on <i>all</i> of them. It did not: <c>DeriveKey</c>,
/// <c>UnwrapKey</c>, <c>EncapsulateKey</c>, <c>DecapsulateKey</c> and <c>UnwrapKeyAuthenticated</c>
/// enforced it while <c>GenerateKey</c>, <c>GenerateKeyPair</c>, <c>CreateObject</c> and
/// <c>CopyObject</c> did not — so the same template that was refused through a derive sailed through
/// a generate, which is the more direct way to defeat the non-extractable posture.
/// </para>
/// <para>
/// The per-operation refusals live in <c>KeyCreationSecureDefaultsTests</c>, whose <c>Operations</c>
/// list now enumerates all nine creation paths. What is left here are the two properties that list
/// cannot express: that the gate refuses rather than disables, and that it does not push secret-key
/// defaults onto a public-key template.
/// </para>
/// </remarks>
public sealed class SecureDefaultsGateCoverageTests
{
    private static (Pkcs11Library Library, Pkcs11Workspace Workspace) New()
    {
        var library = ManagedToken.NewLibrary();
        return (library, ManagedToken.OpenWorkspace(library));
    }

    private static ObjectTemplate WeakSecretKey(bool viaExtractable) =>
        viaExtractable
            ? ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("gate").ValueLen(32).Extractable().Build()
            : ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label("gate").ValueLen(32).Sensitive(false).Build();

    /// <summary>
    /// The gate refuses; it does not disable. With the opt-in the same templates go through, which is
    /// what the library's own extract-and-read helpers rely on.
    /// </summary>
    [Fact]
    public void WithAllowInsecure_TheSameTemplatesAreAccepted()
    {
        var (library, workspace) = New();
        using (library)
        using (workspace)
        {
            workspace.AllowInsecure = true;

            using var tpl = WeakSecretKey(viaExtractable: true);
            using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), tpl);
            Assert.NotNull(key);
        }
    }

    /// <summary>
    /// A public-key template is not a key-protection template: <c>CKA_SENSITIVE</c> and
    /// <c>CKA_EXTRACTABLE</c> do not belong on it, so the gate must not seed them there — the token
    /// would reject the attributes outright.
    /// </summary>
    [Fact]
    public void PublicKeyTemplate_IsNotGivenSecretKeyDefaults()
    {
        var (library, workspace) = New();
        using (library)
        using (workspace)
        {
            using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_EC)
                .Label("pubdefaults").EcParams(TestKeys.EcP256Oid).Build();
            using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_EC).Label("pubdefaults").Derive().Build();

            Assert.Null(Record.Exception(
                () => workspace.GenerateKey(new Mechanism(CKM.CKM_EC_KEY_PAIR_GEN), privTpl, pubTpl).Dispose()));
        }
    }
}
