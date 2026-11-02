using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Xunit.Sdk;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>The skip-or-fail rule of <see cref="ExampleRunner"/>, against a backend that advertises nothing.</summary>
public sealed class ExampleRunnerTests
{
    private static readonly ExampleCase NeedsGcm = new(
        "Fake.NeedsGcm", [], [CKM.CKM_AES_GCM], ExampleBackend.Kryoptic, _ => { });

    [Fact]
    public void Run_RequiredBackendMissingMechanism_FailsUnderCoverage()
    {
        var ex = Assert.Throws<XunitException>(() =>
            ExampleRunner.Run(new NoMechanismBackend(), ExampleBackend.Kryoptic, NeedsGcm, coverageRequired: true));
        Assert.Contains("Fake.NeedsGcm", ex.Message, StringComparison.Ordinal);
        Assert.Contains("CKM_AES_GCM", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_OptionalBackendMissingMechanism_Skips()
    {
        Assert.IsType<SkipException>(Caught(() =>
            ExampleRunner.Run(new NoMechanismBackend(), ExampleBackend.SoftHsm2, NeedsGcm, coverageRequired: true)));
    }

    [Fact]
    public void Run_RequiredBackendMissingMechanism_SkipsWithoutCoverage()
    {
        Assert.IsType<SkipException>(Caught(() =>
            ExampleRunner.Run(new NoMechanismBackend(), ExampleBackend.Kryoptic, NeedsGcm, coverageRequired: false)));
    }

    // Assert.Throws lets xUnit's skip exception through, which would skip the test instead of checking it.
    private static Exception? Caught(Action action)
    {
        try
        {
            action();
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    private sealed class NoMechanismBackend : IPkcs11Backend
    {
        public string LibraryPath => "none";
        public Pkcs11Library Library => throw new NotSupportedException();
        public NativeCULong SlotId => default;
        public ReadOnlyMemory<byte> SoPin => default;
        public ReadOnlyMemory<byte> UserPin => default;
        public string TokenLabel => "none";
        public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();
        public bool Supports(CKM mechanism) => false;
    }
}
