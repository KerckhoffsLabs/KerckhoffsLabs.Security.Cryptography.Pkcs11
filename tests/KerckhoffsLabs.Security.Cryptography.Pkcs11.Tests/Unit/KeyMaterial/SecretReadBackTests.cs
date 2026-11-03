using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.KeyMaterial;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;
using Microsoft.Extensions.Logging;

#pragma warning disable KLPKCS11012 // the export opt-in is what opens the read-backs under test

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.KeyMaterial;

// A read-back secret is zeroed on every failure after it was read: the caller never receives it, so nothing may
// leave it behind in managed memory. The value is observed through the check callback, which is handed the array
// the flow will return. Each read-back is a real one, opened on a ManagedSoftToken session under a KdfOutput
// opt-in, over an HKDF derivation.
[Collection(FakeModuleCollection.Name)]
public sealed class SecretReadBackTests
{
    private const int Length = 32;

    private static readonly byte[] Ikm = Convert.FromHexString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");

    private static ReadBackFailures Failures => ReadBackFailures.KdfOutput;

    private static readonly ICryptoPolicy KdfOptIn = CryptoPolicy.Recommended.ToBuilder("Opt-in")
        .WithKeyMaterialExportRule(KeyMaterialExportRule.Allow([KeyMaterialExportKind.KdfOutput], "test", KdfBaseKeyScope.NeverProtected))
        .Build();

    private sealed class Probe
    {
        public byte[]? Seen { get; private set; }
        public void Capture(byte[] value) => Seen = value;
    }

    // Throws from every Warning entry: the export report's first line for a kind.
    private sealed class ThrowingOnWarningLogger : ILogger
    {
        IDisposable? ILogger.BeginScope<TState>(TState state) => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
                throw new InvalidOperationException("log sink down");
        }
    }

    // Runs body over an opted-in session, an HKDF base key and the ephemeral key factory a read-back would use.
    private static void WithReadBack(ILogger? logger, Action<Pkcs11Session, Func<IReadBackGrant, Pkcs11Key>> body)
    {
        using var library = new ManagedSoftToken().Load(
            logger is null ? null : new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(logger) });
        using var session = ManagedToken.OpenSession(library, KdfOptIn);
        using var ikmTemplate = ObjectTemplate.ForSecretKey(CKK.CKK_GENERIC_SECRET).Value(Ikm).Derive().Build();
        using var ikm = session.ImportKey(ikmTemplate);
        using var template = Pkcs11.Algorithms.DerivedKeyMaterial.ExtractableSecretTemplate(Length);
        var mechanism = new Mechanism(CKM.CKM_HKDF_DERIVE,
            CkmHkdfParams.WithSalt(HkdfOperation.ExtractAndExpand, CKM.CKM_SHA256, [1, 2, 3], [4, 5]));
        body(session, grant => ikm.Derive(mechanism, template, grant));
    }

    [Fact]
    public void ExportReportThatThrows_ZeroesTheSecret() => WithReadBack(new ThrowingOnWarningLogger(), (session, create) =>
    {
        var probe = new Probe();
        using SecretReadBack readBack = session.BeginReadBack(KeyMaterialExportKind.KdfOutput);

        var e = Assert.Throws<InvalidOperationException>(() => readBack.Read(create, Length, Failures, probe.Capture));

        Assert.Equal("log sink down", e.Message);
        Assert.NotNull(probe.Seen);
        Assert.All(probe.Seen, b => Assert.Equal(0, b));
    });

    [Fact]
    public void DestroyThatThrowsANonPkcs11Exception_ZeroesTheSecret() => WithReadBack(null, (session, create) =>
    {
        var probe = new Probe();
        Pkcs11Key? ephemeral = null;
        using SecretReadBack readBack = session.BeginReadBack(KeyMaterialExportKind.KdfOutput);

        // Disposing the key from the check makes the following Destroy throw ObjectDisposedException.
        Assert.Throws<ObjectDisposedException>(() => readBack.Read(
            grant => ephemeral = create(grant), Length, Failures, v => { probe.Capture(v); ephemeral!.Dispose(); }));

        Assert.NotNull(probe.Seen);
        Assert.All(probe.Seen, b => Assert.Equal(0, b));
    });

    // The cleanup destroy after a failed check must never replace the failure being reported, whatever it throws.
    [Fact]
    public void FailedCheck_CleanupDestroyThatThrowsANonPkcs11Exception_KeepsTheCheckFailure() => WithReadBack(null, (session, create) =>
    {
        var probe = new Probe();
        Pkcs11Key? ephemeral = null;
        using SecretReadBack readBack = session.BeginReadBack(KeyMaterialExportKind.KdfOutput);

        var e = Assert.Throws<CryptographicException>(() => readBack.Read(
            grant => ephemeral = create(grant), Length, Failures, v =>
            {
                probe.Capture(v);
                ephemeral!.Dispose(); // the cleanup Destroy now throws ObjectDisposedException
                throw new CryptographicException("check failed");
            }));

        Assert.Equal("check failed", e.Message);
        Assert.NotNull(probe.Seen);
        Assert.All(probe.Seen, b => Assert.Equal(0, b));
    });

    [Fact]
    public void SuccessfulRead_ReturnsTheSecretAndReportsOnce()
    {
        var log = new CapturingLogger();
        WithReadBack(log, (session, create) =>
        {
            log.Clear();
            using SecretReadBack readBack = session.BeginReadBack(KeyMaterialExportKind.KdfOutput);

            byte[] value = readBack.Read(create, Length, Failures);

            Assert.Equal(Length, value.Length);
            Assert.Single(log.Entries, e => e.Message.Contains("allowed export of KdfOutput", StringComparison.Ordinal));
            CryptographicOperations.ZeroMemory(value);
        });
    }
}
