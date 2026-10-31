using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.MemoryLeaks;

/// <summary>
/// Reading derived key material off the token must not leave it in unmanaged memory.
/// </summary>
/// <remarks>
/// <para>
/// The read-back path asks the token for <c>CKA_VALUE</c> and gets back <c>ObjectAttribute</c>
/// instances that own unmanaged buffers holding the derived secret. Disposing them is what frees
/// <i>and zeroizes</i> those buffers — <c>UnmanagedMemory.Free</c> wipes before releasing — so
/// forgetting to dispose leaks the secret in cleartext for the life of the process, silently and with
/// no functional symptom.
/// </para>
/// <para>
/// <c>SP800108HmacCounterKdfPkcs11</c> did exactly that, while its <c>ECDiffieHellmanPkcs11</c>
/// sibling disposed them; the divergence is why this is asserted rather than assumed.
/// </para>
/// </remarks>
[Collection("MemoryLeaks")]
public sealed class DerivedKeyMaterialLeakTests
{
    private static readonly byte[] KeyBytes =
        [.. Enumerable.Range(0, 32).Select(i => (byte)(i + 1))];

    // The allocation count is process-wide, so undisposed objects left by earlier tests are in it too,
    // and their finalizers free them whenever the GC gets round to it — mid-loop included, which drags
    // the count below the baseline. Settle them before taking the snapshot, as MechanismParamsLeakTests
    // does.
    private static int SettledAllocationCount()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        return UnmanagedMemory.OutstandingAllocationCount;
    }

    [Fact]
    public void Sp800108Derive_LeavesNothingInUnmanagedMemory()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // reading derived bytes back is gated
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("kdf-leak").Value(KeyBytes).Derive().Build();
        using var key = session.ImportKey(tpl);
        using var kdf = new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256);

        // Warm up first: the first call through a path allocates caches and one-time state that would
        // otherwise read as a leak.
        _ = kdf.DeriveKey("label"u8.ToArray(), "context"u8.ToArray(), 32);

        int before = SettledAllocationCount();

        for (int i = 0; i < 8; i++)
            _ = kdf.DeriveKey("label"u8.ToArray(), "context"u8.ToArray(), 32);

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    /// <summary>
    /// The sibling path, which already disposed its attributes — kept so a future refactor cannot
    /// regress one while fixing the other.
    /// </summary>
    [Fact]
    public void EcdhRawSecret_LeavesNothingInUnmanagedMemory()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var insecure = session.UsePolicy(CryptoPolicy.AllowInsecure); // DeriveRawSecretAgreement hands Z to the caller and is gated
        using var key = session.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        using var peer = ECDiffieHellman.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        _ = ecdh.DeriveRawSecretAgreement(peer.PublicKey);

        int before = SettledAllocationCount();

        for (int i = 0; i < 8; i++)
            _ = ecdh.DeriveRawSecretAgreement(peer.PublicKey);

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    /// <summary>
    /// The secure defaults appended to SP 800-108 sibling templates own unmanaged buffers: they must be
    /// released after a derive, and also when a later sibling is refused after earlier ones were built.
    /// </summary>
    [Fact]
    public void Sp800108SiblingDefaults_LeaveNothingInUnmanagedMemory()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.Recommended);
        using var baseTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("kdf-sibling-leak").Value(KeyBytes).Derive().Build();
        using var baseKey = session.ImportKey(baseTpl);

        // Omits CKA_SENSITIVE / CKA_EXTRACTABLE, so the session builds defaults for it.
        using var accepted = new ReadOnlyDisposableList<ObjectAttribute>(
        [
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
            new ObjectAttribute(CKA.CKA_VALUE_LEN, 16UL),
        ]);
        using var refused = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(16).Sensitive(false).Build();
        using var primaryTpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).ValueLen(32).Build();

        void DeriveOnce()
        {
            CkmSp800108KdfParams kdfParams = SiblingParams(accepted);
            var ok = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, kdfParams);
            using (Pkcs11Key primary = baseKey.Derive(ok, primaryTpl))
            {
                using Pkcs11Key sibling = kdfParams.AdditionalDerivedKeys[0]!;
                sibling.Destroy();
                primary.Destroy();
            }

            var bad = new Mechanism(CKM.CKM_SP800_108_COUNTER_KDF, SiblingParams(accepted, [.. refused.Attributes]));
            Assert.Throws<CryptoPolicyViolationException>(() => baseKey.Derive(bad, primaryTpl));
        }

        DeriveOnce(); // warm-up

        int before = SettledAllocationCount();
        for (int i = 0; i < 8; i++)
            DeriveOnce();

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }

    private static CkmSp800108KdfParams SiblingParams(params IReadOnlyList<ObjectAttribute>[] siblings)
    {
        var builder = CkmSp800108KdfParams.Counter(CKM.CKM_SHA256_HMAC)
            .IterationCounter().ByteArray("label"u8.ToArray()).ByteArray([0x00]).ByteArray("context"u8.ToArray())
            .DkmLength(Sp800108DkmLengthMethod.SumOfKeys);
        foreach (var sibling in siblings)
            builder.AddDerivedKey(sibling);
        return builder.Build();
    }
}
