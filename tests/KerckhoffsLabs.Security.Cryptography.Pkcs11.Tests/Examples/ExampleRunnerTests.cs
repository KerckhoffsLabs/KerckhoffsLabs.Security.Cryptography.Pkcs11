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

    private static readonly ExampleCase GatedOff = new(
        "Fake.GatedOff", [], [], ExampleBackend.Kryoptic, _ => { }, Unsupported: _ => "this backend's AES-GCM is broken");

    private static readonly ExampleCase SkipsInside = new(
        "Fake.SkipsInside", [], [], ExampleBackend.Kryoptic, _ => Assert.Skip("the platform lacks it"));

    private static readonly ExampleCase LogsIn = new(
        "Fake.LogsIn", [], [], ExampleBackend.Nss, _ => { }, NeedsUserLogin: true);

    [Fact]
    public void Run_UnsupportedOnRequiredBackend_FailsUnderCoverage()
    {
        var ex = Assert.Throws<XunitException>(() =>
            ExampleRunner.Run(new NoMechanismBackend(), ExampleBackend.Kryoptic, GatedOff, coverageRequired: true));
        Assert.Contains("AES-GCM is broken", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_UnsupportedOnOptionalBackend_Skips() =>
        Assert.IsType<SkipException>(Caught(() =>
            ExampleRunner.Run(new NoMechanismBackend(), ExampleBackend.SoftHsm2, GatedOff, coverageRequired: true)));

    [Fact]
    public void Run_SkipInsideRequiredExample_FailsUnderCoverage()
    {
        var ex = Assert.Throws<XunitException>(() =>
            ExampleRunner.Run(new NoMechanismBackend(), ExampleBackend.Kryoptic, SkipsInside, coverageRequired: true));
        Assert.Contains("Fake.SkipsInside", ex.Message, StringComparison.Ordinal);
        Assert.Contains("the platform lacks it", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_SkipInsideExample_SkipsWithoutCoverage() =>
        Assert.IsType<SkipException>(Caught(() =>
            ExampleRunner.Run(new NoMechanismBackend(), ExampleBackend.Kryoptic, SkipsInside, coverageRequired: false)));

    [Fact]
    public void Run_NeedsUserLoginOnLoginlessRequiredBackend_FailsUnderCoverage()
    {
        var ex = Assert.Throws<XunitException>(() =>
            ExampleRunner.Run(new LoginlessBackend(), ExampleBackend.Nss, LogsIn, coverageRequired: true));
        Assert.Contains("no user login", ex.Message, StringComparison.Ordinal);
    }

    private sealed class LoginlessBackend : IPkcs11Backend
    {
        public string LibraryPath => "none";
        public Pkcs11Library Library => throw new NotSupportedException();
        public NativeCULong SlotId => default;
        public ReadOnlyMemory<byte> SoPin => default;
        public ReadOnlyMemory<byte> UserPin => default;
        public string TokenLabel => "none";
        public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();
        public bool Supports(CKM mechanism) => true;
        public bool RequiresUserLogin => false;
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
