using System.Security.Cryptography;
using Pkcs11ECCurve = KerckhoffsLabs.Security.Cryptography.Pkcs11.ECCurve;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

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

    [Fact]
    public void Sp800108Derive_LeavesNothingInUnmanagedMemory()
    {
        using var library = ManagedToken.NewLibrary();
        using var workspace = ManagedToken.OpenWorkspace(library);
        using var tpl = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET)
            .Label("kdf-leak").Value(KeyBytes).Derive().Build();
        using var key = workspace.ImportKey(tpl);
        using var kdf = new SP800108HmacCounterKdfPkcs11(key, HashAlgorithmName.SHA256);

        // Warm up first: the first call through a path allocates caches and one-time state that would
        // otherwise read as a leak.
        _ = kdf.DeriveKey("label"u8.ToArray(), "context"u8.ToArray(), 32);

        int before = UnmanagedMemory.OutstandingAllocationCount;

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
        using var workspace = ManagedToken.OpenWorkspace(library);
        workspace.AllowInsecure = true; // DeriveRawSecretAgreement hands Z to the caller and is gated
        using var key = workspace.GenerateEcKeyPair(Pkcs11ECCurve.NamedCurves.NistP256);
        using var ecdh = new ECDiffieHellmanPkcs11(key);
        using var peer = ECDiffieHellman.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);

        _ = ecdh.DeriveRawSecretAgreement(peer.PublicKey);

        int before = UnmanagedMemory.OutstandingAllocationCount;

        for (int i = 0; i < 8; i++)
            _ = ecdh.DeriveRawSecretAgreement(peer.PublicKey);

        Assert.Equal(before, UnmanagedMemory.OutstandingAllocationCount);
    }
}
