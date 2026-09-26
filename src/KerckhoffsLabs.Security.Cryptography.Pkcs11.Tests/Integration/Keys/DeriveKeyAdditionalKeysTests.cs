using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// End-to-end coverage for <c>CkmSp800108KdfParams.AdditionalDerivedKeys</c>: sibling keys requested
/// alongside the primary <c>C_DeriveKey</c> call must come back as usable, destroyable
/// <see cref="Pkcs11Key"/> instances, not raw handles nothing on the public surface can consume.
/// Neither SoftHSM nor opencryptoki implements this mechanism, so the in-process managed fake is the
/// only backend that exercises it (see <c>Sp800108KdfTests</c> for the hermetic marshalling coverage).
/// </summary>
[NoBackendCollection("Drives a per-test ManagedSoftToken in process — no native module is loaded and " +
                     "the token holds no static state, so this is safe alongside every backend collection.")]
public sealed class DeriveKeyAdditionalKeysTests
{
    private static readonly byte[] BaseKeyBytes = [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 1))];

    [Fact]
    public void AdditionalDerivedKeys_AreUsableAndDestroyable()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var insecure = workspace.UsePolicy(CryptoPolicy.AllowInsecure); // sibling templates below request extractable material

        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("sp800108-base").Value(BaseKeyBytes).Derive().Build();
        using var baseKey = workspace.ImportKey(baseTpl);

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
        using var workspace = ManagedToken.OpenWorkspace(library);

        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("sp800108-base-plain").Value(BaseKeyBytes).Derive().Build();
        using var baseKey = workspace.ImportKey(baseTpl);

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
}
