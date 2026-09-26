using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Confirms <c>Pkcs11Workspace.GenerateAesKeyEncryptionKey</c>'s documented security guarantee is
/// actually enforced by a real backend, not just marshalled correctly: its <c>CKA_WRAP_TEMPLATE</c>
/// (only CKA_SENSITIVE keys are wrappable) and <c>CKA_UNWRAP_TEMPLATE</c> (every unwrapped key is
/// forced CKA_SENSITIVE/non-extractable) actually constrain wrap/unwrap, not just marshal cleanly.
/// </summary>
/// <remarks>
/// Prompted by noticing Kryoptic gained real support for these PKCS#11 template attributes
/// (CKA_WRAP_TEMPLATE/CKA_UNWRAP_TEMPLATE/CKA_DERIVE_TEMPLATE) upstream. Before this, the only
/// coverage anywhere in this project was <c>NestedTemplateOwnershipTests</c>, a pure unit test for
/// marshalling/memory-ownership correctness — never against a backend that actually enforces the
/// template, despite <c>GenerateAesKeyEncryptionKey</c>'s own doc comment promising exactly that
/// enforcement as a security property.
/// <para>
/// Checked directly, not assumed, against every backend's actual source (not a debug name table):
/// NSS registers the CKA_*_TEMPLATE constants but its C_WrapKey/C_UnwrapKey implementation
/// (pkcs11c.c) never reads them — not enforced. SoftHSM2 and Kryoptic both genuinely enforce
/// CKA_WRAP_TEMPLATE and CKA_UNWRAP_TEMPLATE.
/// </para>
/// <para>
/// <b>A source-reading correction worth recording:</b> SoftHSM.cpp's C_UnwrapKey appears, on a
/// static read, to require the caller's template to explicitly restate every attribute
/// CKA_UNWRAP_TEMPLATE imposes (failing an *omitted* one with CKR_TEMPLATE_INCONSISTENT exactly
/// like a conflicting one) — a stricter behavior than Kryoptic's merge-and-inherit. Driving it for
/// real disproved that: SoftHSM2 actually merges and inherits omitted attributes identically to
/// Kryoptic (confirmed via <c>Assert_Unwrap_OmittedAttributeTemplate_TreatsAsInherited</c>, which
/// passes on both). The exact mechanism in SoftHSM.cpp that reconciles this with the code that
/// looks that way in isolation wasn't tracked down further; the empirical result is what these
/// tests pin, not the source-reading guess.
/// </para>
/// <para>
/// CKA_WRAP_TEMPLATE's filter-mismatch case is enforced by both, but with a different CKR
/// (CKR_ACTION_PROHIBITED on Kryoptic, CKR_KEY_NOT_WRAPPABLE on SoftHSM2), so that case asserts any
/// <see cref="Pkcs11Exception"/> rather than pinning one code. Kryoptic also supports
/// CKA_DERIVE_TEMPLATE, CKA_ENCAPSULATE_TEMPLATE, and CKA_DECAPSULATE_TEMPLATE, which SoftHSM2 does
/// not implement at all (confirmed absent from SoftHSM.cpp) — out of scope here since
/// GenerateAesKeyEncryptionKey only uses wrap/unwrap templates.
/// </para>
/// </remarks>
internal static class KekTemplateEnforcementTestCases
{
    private static Pkcs11Workspace OpenWorkspace(IPkcs11Backend backend) => backend.OpenWorkspace();

    // Matches the wrap-template filter (CKA_SENSITIVE) and is extractable, so it's wrappable at all.
    private static Pkcs11Key GenerateWrappableTargetKey(Pkcs11Workspace workspace) =>
        workspace.GenerateKey(
            new Mechanism(CKM.CKM_AES_KEY_GEN),
            ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Sensitive().Extractable().Build());

    // Fails the wrap-template filter (CKA_SENSITIVE = false), otherwise identical. CKA_SENSITIVE=false
    // is itself gated by GuardInsecureKeyAttributes (a plaintext-readable-off-token key), so this
    // deliberately-insecure key needs the same opt-in -- unrelated to the CKA_WRAP_TEMPLATE gate this
    // test exercises, just a prerequisite for constructing the mismatching key at all.
    private static Pkcs11Key GenerateNonWrappableTargetKey(Pkcs11Workspace workspace)
    {
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure);
        return workspace.GenerateKey(
            new Mechanism(CKM.CKM_AES_KEY_GEN),
            ObjectTemplate.ForSecretKey(CKK.CKK_AES).ValueLen(32).Sensitive(false).Extractable().Build());
    }

    // Plain RFC 3394 wrap (no padding, no IV parameter) -- the 32-byte AES key is already
    // block-aligned, so there's no need for KWP's odd-length handling, and this is the one AES
    // key-wrap mechanism confirmed supported by both Kryoptic and SoftHSM2.
    private static byte[] Wrap(Pkcs11Key kek, Pkcs11Key target) =>
        kek.Wrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), target);

    private static Pkcs11Key Unwrap(Pkcs11Key kek, byte[] wrapped, ObjectTemplate template) =>
        kek.Unwrap(new Mechanism(CKM.CKM_AES_KEY_WRAP), wrapped, template);

    private static bool GetBoolAttr(Pkcs11Workspace workspace, Pkcs11Key key, CKA attr)
    {
        using var attrs = workspace.Session.GetAttributeValue(key.PrivateHandle, [attr]);
        return attrs[0].GetValueAsBool();
    }

    // === CKA_WRAP_TEMPLATE (filter) ==========================================

    internal static void Assert_Wrap_SensitiveTargetKey_Succeeds(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_WRAP);
        using var workspace = OpenWorkspace(backend);
        using var kek = workspace.GenerateAesKeyEncryptionKey();
        using var target = GenerateWrappableTargetKey(workspace);

        byte[] wrapped = Wrap(kek, target);
        Assert.NotEmpty(wrapped);
    }

    // Exact CKR differs by backend (CKR_ACTION_PROHIBITED on Kryoptic, CKR_KEY_NOT_WRAPPABLE on
    // SoftHSM2) -- see the class remarks -- so this asserts rejection generically.
    internal static void Assert_Wrap_NonSensitiveTargetKey_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_WRAP);
        using var workspace = OpenWorkspace(backend);
        using var kek = workspace.GenerateAesKeyEncryptionKey();
        using var target = GenerateNonWrappableTargetKey(workspace);

        Assert.ThrowsAny<Pkcs11Exception>(() => Wrap(kek, target));
    }

    // === CKA_UNWRAP_TEMPLATE (imposition) — behavior shared by both backends ==

    internal static void Assert_Unwrap_ExplicitMatchingTemplate_Succeeds(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_WRAP);
        using var workspace = OpenWorkspace(backend);
        using var kek = workspace.GenerateAesKeyEncryptionKey();
        using var target = GenerateWrappableTargetKey(workspace);
        byte[] wrapped = Wrap(kek, target);

        // Explicitly restates the values CKA_UNWRAP_TEMPLATE imposes (Sensitive=true,
        // Extractable=false) — matches on both Kryoptic and SoftHSM2.
        using var unwrapTemplate = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Sensitive().NonExtractable().Build();
        using var unwrapped = Unwrap(kek, wrapped, unwrapTemplate);

        Assert.True(GetBoolAttr(workspace, unwrapped, CKA.CKA_SENSITIVE));
        Assert.False(GetBoolAttr(workspace, unwrapped, CKA.CKA_EXTRACTABLE));
    }

    // Both backends agree on CKR_TEMPLATE_INCONSISTENT for an explicit conflict (unlike the
    // omission case below, where they diverge) — pinned, not just "any exception".
    internal static void Assert_Unwrap_ExplicitConflictingTemplate_Throws(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_WRAP);
        using var workspace = OpenWorkspace(backend);
        using var kek = workspace.GenerateAesKeyEncryptionKey();
        using var target = GenerateWrappableTargetKey(workspace);
        byte[] wrapped = Wrap(kek, target);

        // Explicitly requests Extractable=true, conflicting with the KEK's imposed false.
        using var unwrapTemplate = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Extractable().Build();

        var ex = Assert.ThrowsAny<Pkcs11Exception>(() => Unwrap(kek, wrapped, unwrapTemplate));
        Assert.Equal(CKR.CKR_TEMPLATE_INCONSISTENT, ex.ReturnValue);
    }

    // === CKA_UNWRAP_TEMPLATE — omission handling, confirmed identical on both backends =

    internal static void Assert_Unwrap_OmittedAttributeTemplate_TreatsAsInherited(IPkcs11Backend backend)
    {
        backend.RequireMechanisms(CKM.CKM_AES_KEY_WRAP);
        using var workspace = OpenWorkspace(backend);
        using var kek = workspace.GenerateAesKeyEncryptionKey();
        using var target = GenerateWrappableTargetKey(workspace);
        byte[] wrapped = Wrap(kek, target);

        // No CKA_EXTRACTABLE/CKA_SENSITIVE at all -- ObjectTemplate.Empty() has no builder defaults
        // to work around (unlike ForSecretKey(), which always states both explicitly).
        using var unwrapTemplate = ObjectTemplate.Empty()
            .Attribute(CKA.CKA_CLASS, (ulong)CKO.CKO_SECRET_KEY)
            .Attribute(CKA.CKA_KEY_TYPE, (ulong)CKK.CKK_AES)
            .Build();
        using var unwrapped = Unwrap(kek, wrapped, unwrapTemplate);

        Assert.True(GetBoolAttr(workspace, unwrapped, CKA.CKA_SENSITIVE));
        Assert.False(GetBoolAttr(workspace, unwrapped, CKA.CKA_EXTRACTABLE));
    }
}
