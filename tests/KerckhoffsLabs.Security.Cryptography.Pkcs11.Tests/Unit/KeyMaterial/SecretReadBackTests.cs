using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.KeyMaterial;

// A read-back secret is zeroed on every failure after it was read: the caller never receives it, so nothing may
// leave it behind in managed memory. The value is observed through the check callback, which is handed the array
// the flow will return.
[Collection(FakeModuleCollection.Name)]
public sealed class SecretReadBackTests
{
    private static readonly byte[] Secret = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    private static ReadBackFailures Failures => ReadBackFailures.KdfOutput;

    private static FakeKey SecretKey() => FakeKeys.Create(
        CKK.CKK_GENERIC_SECRET,
        ca => ca == CKA.CKA_VALUE ? (CKR.CKR_OK, Secret.ToArray()) : (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        allowDestroy: true);

    private sealed class Probe : IDisposable
    {
        public byte[]? Seen { get; private set; }
        public void Capture(byte[] value) => Seen = value;
        public void Dispose() { }
    }

    [Fact]
    public void ExportReportThatThrows_ZeroesTheSecret()
    {
        using FakeKey fake = SecretKey();
        var probe = new Probe();
        using var readBack = new SecretReadBack(() => throw new InvalidOperationException("log sink down"), probe);

        var e = Assert.Throws<InvalidOperationException>(
            () => readBack.Read(() => fake.Key, Secret.Length, Failures, probe.Capture));

        Assert.Equal("log sink down", e.Message);
        Assert.NotNull(probe.Seen);
        Assert.All(probe.Seen, b => Assert.Equal(0, b));
    }

    [Fact]
    public void DestroyThatThrowsANonPkcs11Exception_ZeroesTheSecret()
    {
        using FakeKey fake = SecretKey();
        var probe = new Probe();
        using var readBack = new SecretReadBack(() => { }, probe);

        // Disposing the key from the check makes the following Destroy throw ObjectDisposedException.
        Assert.Throws<ObjectDisposedException>(
            () => readBack.Read(() => fake.Key, Secret.Length, Failures, v => { probe.Capture(v); fake.Key.Dispose(); }));

        Assert.NotNull(probe.Seen);
        Assert.All(probe.Seen, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SuccessfulRead_ReturnsTheSecretAndReportsOnce()
    {
        using FakeKey fake = SecretKey();
        int reports = 0;
        using var readBack = new SecretReadBack(() => reports++, new Probe());

        byte[] value = readBack.Read(() => fake.Key, Secret.Length, Failures);

        Assert.Equal(Secret, value);
        Assert.Equal(1, reports);
        CryptographicOperations.ZeroMemory(value);
    }
}
