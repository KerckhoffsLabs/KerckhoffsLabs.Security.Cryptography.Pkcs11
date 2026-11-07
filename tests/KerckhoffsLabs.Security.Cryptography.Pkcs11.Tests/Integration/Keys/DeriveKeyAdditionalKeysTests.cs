using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// End-to-end coverage for <c>CkmSp800108KdfParams.AdditionalDerivedKeys</c>: sibling keys requested
/// alongside the primary <c>C_DeriveKey</c> call must come back as usable, destroyable
/// <see cref="Pkcs11Key"/> instances, not raw handles nothing on the public surface can consume.
/// Neither SoftHSM nor opencryptoki implements this mechanism, so the in-process managed fake is the
/// only backend that exercises it (see <c>Sp800108KdfTests</c> for the hermetic marshalling coverage).
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class DeriveKeyAdditionalKeysTests
{
    private static readonly byte[] BaseKeyBytes = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 1))];

    [Fact]
    public void AdditionalDerivedKeys_AreUsableAndDestroyable()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // sibling templates below request extractable material

        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("sp800108-base").Value(BaseKeyBytes).Derive().Build();
        using var baseKey = session.ImportKey(baseTpl);

        using var siblingTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(16).Extractable().Sensitive(false).Build();

        var kdfParams = CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray("label"u8.ToArray()).ByteArray([0x00]).ByteArray("context"u8.ToArray())
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys)
            .AddDerivedKey([.. siblingTpl.Attributes])
            .Build();
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdfParams);

        using var primaryTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        // Before the call: the mechanism owns the description, not yet any handles.
        Assert.Empty(kdfParams.AdditionalDerivedKeys);

        using Pkcs11Key primary = baseKey.Derive(mechanism, primaryTpl);
        try
        {
            var siblings = kdfParams.AdditionalDerivedKeys;
            Pkcs11Key? sibling = Assert.Single(siblings);
            Assert.NotNull(sibling);

            try
            {
                // Usable: a real Pkcs11Key operation succeeds, not just a stashed integer.
                using var siblingAttrs = sibling.GetAttributeValue(CKA.CKA_VALUE);
                Assert.False(siblingAttrs[0].CannotBeRead);
                Assert.Equal(16, siblingAttrs[0].GetValueAsByteArray().Length);

                // A snapshot: re-reading the property returns the same key instance.
                Assert.Same(sibling, kdfParams.AdditionalDerivedKeys[0]);
            }
            finally
            {
                // Destroyable: previously nothing on the public surface could reach this call.
                sibling.Destroy();
            }
        }
        finally
        {
            primary.Destroy();
        }
    }

    [Fact]
    public void NoAdditionalDerivedKeysRequested_PropertyStaysEmptyAfterDerive()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);

        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("sp800108-base-plain").Value(BaseKeyBytes).Derive().Build();
        using var baseKey = session.ImportKey(baseTpl);

        var kdfParams = CkmSp800108KdfParams.CounterModeHmac(CKM.CKM_SHA256_HMAC, "label"u8.ToArray(), "context"u8.ToArray());
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdfParams);

        using var primaryTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        using Pkcs11Key primary = baseKey.Derive(mechanism, primaryTpl);
        try
        {
            Assert.Empty(kdfParams.AdditionalDerivedKeys);
        }
        finally
        {
            primary.Destroy();
        }
    }

    // ---- Policy: each sibling template is judged and defaulted like the primary one ----

    private static CkmSp800108KdfParams CounterParamsWithSibling(IReadOnlyList<ObjectAttribute> siblingTemplate) =>
        CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray("label"u8.ToArray()).ByteArray([0x00]).ByteArray("context"u8.ToArray())
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys)
            .AddDerivedKey(siblingTemplate)
            .Build();

    [Fact]
    public void NonSensitiveSibling_UnderRecommended_IsRefusedBeforeTheToken()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.Recommended);

        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("sp800108-base-policy").Value(BaseKeyBytes).Derive().Build();
        using var baseKey = session.ImportKey(baseTpl);

        // The primary template is secure; only the sibling asks for readable key material.
        using var siblingTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(16).Extractable().Sensitive(false).Build();
        var kdfParams = CounterParamsWithSibling([.. siblingTpl.Attributes]);
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdfParams);
        using var primaryTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        Assert.Throws<CryptoPolicyViolationException>(() => baseKey.Derive(mechanism, primaryTpl));

        Assert.Equal(0, token.DeriveKeyCallCount);
        Assert.Empty(kdfParams.AdditionalDerivedKeys);
    }

    [Fact]
    public void SiblingOmittingSensitiveAndExtractable_GetsTheSecureDefaults()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.Recommended);

        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("sp800108-base-defaults").Value(BaseKeyBytes).Derive().Build();
        using var baseKey = session.ImportKey(baseTpl);

        // Raw attributes: the template builders always set CKA_SENSITIVE / CKA_EXTRACTABLE themselves.
        using var siblingTpl = new ReadOnlyDisposableList<ObjectAttribute>(
        [
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
            new ObjectAttribute(CKA.CKA_VALUE_LEN, 16UL),
        ]);
        var kdfParams = CounterParamsWithSibling(siblingTpl);
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdfParams);
        using var primaryTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        using Pkcs11Key primary = baseKey.Derive(mechanism, primaryTpl);
        using Pkcs11Key? sibling = Assert.Single(kdfParams.AdditionalDerivedKeys);
        Assert.NotNull(sibling);
        try
        {
            using var attrs = sibling.GetAttributeValue(CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE);
            Assert.True(attrs[0].GetValueAsBool());
            Assert.False(attrs[1].GetValueAsBool());
        }
        finally
        {
            sibling.Destroy();
            primary.Destroy();
        }
    }

    [Fact]
    public void NonSensitiveSibling_UnderAllowInsecure_IsStillDerived()
    {
        var token = new ManagedSoftToken();
        using var library = token.Load();
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.AllowInsecure);

        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("sp800108-base-insecure").Value(BaseKeyBytes).Derive().Build();
        using var baseKey = session.ImportKey(baseTpl);

        using var siblingTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .ValueLen(16).Extractable().Sensitive(false).Build();
        var kdfParams = CounterParamsWithSibling([.. siblingTpl.Attributes]);
        var mechanism = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdfParams);
        using var primaryTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        using Pkcs11Key primary = baseKey.Derive(mechanism, primaryTpl);
        using Pkcs11Key? sibling = Assert.Single(kdfParams.AdditionalDerivedKeys);
        Assert.NotNull(sibling);
        try
        {
            // The explicit choices reach the token unchanged — no secure default is appended over them.
            using var attrs = sibling.GetAttributeValue(CKA.CKA_SENSITIVE, CKA.CKA_EXTRACTABLE);
            Assert.False(attrs[0].GetValueAsBool());
            Assert.True(attrs[1].GetValueAsBool());
        }
        finally
        {
            sibling.Destroy();
            primary.Destroy();
        }
        Assert.Equal(1, token.DeriveKeyCallCount);
    }
}
