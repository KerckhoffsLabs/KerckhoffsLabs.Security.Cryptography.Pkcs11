using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture for BouncyHsm (harrison314/BouncyHsm): a PKCS#11 v3.x soft HSM whose
/// native client forwards every call over TCP to a .NET server built on BouncyCastle. It is a sixth,
/// independent implementation alongside the mock, SoftHSM2, NSS, Kryoptic and opencryptoki, and the
/// only real backend besides SoftHSM2 that runs on Windows and macOS.
///
/// Built from the vendor/bouncyhsm submodule by the opt-in BuildBouncyHsm MSBuild target
/// (<see cref="Settings.BouncyHsmDirectory"/>). The fixture starts a private, in-memory server
/// (<see cref="BouncyHsmServer"/>), creates one token through its REST API, and points the client at
/// it with <c>BOUNCY_HSM_CFG_STRING</c>, which the client reads when the library loads, so it is set
/// before <see cref="Pkcs11Library.Load(string, Pkcs11LibraryOptions)"/>. Each run starts from a fresh token.
///
/// Known upstream bugs are gated below, one flag each, and
/// <c>Integration/Compat/BouncyHsmQuirkTests</c> fails once a gated bug is fixed.
/// </summary>
public sealed class BouncyHsmBackendFixture : IPkcs11Backend, IDisposable
{
    private readonly BouncyHsmServer? _server;

    public string LibraryPath { get; } = string.Empty;
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = Settings.BouncyHsmTokenLabel;

    /// <summary>Mechanisms the token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True when a BouncyHsm server and a native client for this RID are staged. Never starts a process.</summary>
    public static bool BouncyHsmAvailable => ServerAssemblyPath() is not null && NativeLibraryPath() is not null;

    /// <summary>
    /// False while harrison314/BouncyHsm#115 is open: the client refuses <c>ulDataLen == 0</c> in
    /// <c>C_Digest</c>/<c>C_DigestUpdate</c>/<c>C_Verify</c> (<c>CKR_ARGUMENTS_BAD</c>) and the server refuses to
    /// sign or verify empty data (<c>CKR_GENERAL_ERROR</c>). BouncyHsmQuirkTests.EmptyDigest_QuirkStillPresent
    /// and EmptyHmac_QuirkStillPresent fail once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsEmptyInput = false;

    /// <summary>
    /// False while harrison314/BouncyHsm#116 is open: an RSA-PSS signature whose value is at least the
    /// modulus gives <c>CKR_GENERAL_ERROR</c> instead of <c>CKR_SIGNATURE_INVALID</c>, so a tamper check
    /// fails for about half of all random tamperings.
    /// BouncyHsmQuirkTests.OutOfRangePssSignature_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmRejectsOutOfRangeSignatures = false;

    /// <summary>Gate for empty-input digest and MAC cases: see <see cref="BouncyHsmAcceptsEmptyInput"/>.</summary>
    public static bool EmptyDigestAndMacAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptyInput;

    /// <summary>Gate for cases that verify a tampered RSA-PSS signature: see <see cref="BouncyHsmRejectsOutOfRangeSignatures"/>.</summary>
    public static bool OutOfRangeSignatureRejectionAvailable => BouncyHsmAvailable && BouncyHsmRejectsOutOfRangeSignatures;

    public BouncyHsmBackendFixture()
    {
        if (!BouncyHsmAvailable) return;

        _server = BouncyHsmServer.Start(ServerAssemblyPath()!);
        try
        {
            _server.CreateSlot(TokenLabel, Settings.UserPin, Settings.SoPin);

            string config = $"Server=127.0.0.1; Port={_server.TcpPort}; LogTarget=ErrorConsole; LogLevel=ERROR;";
            Environment.SetEnvironmentVariable("BOUNCY_HSM_CFG_STRING", config);
            SoftHsmBackendFixture.SetNativeEnv("BOUNCY_HSM_CFG_STRING", config);

            LibraryPath = NativeLibraryPath()!;
            Library = Pkcs11Library.Load(LibraryPath);
            Pkcs11Slot slot = Library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException($"BouncyHsm token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
        }
        catch
        {
            try { Library?.Dispose(); } catch { /* best-effort */ }
            _server.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { /* best-effort */ }
        _server?.Dispose();
    }

    internal static string? ServerAssemblyPath()
    {
        string path = Path.Join(Settings.BouncyHsmDirectory, "server", "BouncyHsm.dll");
        return File.Exists(path) ? path : null;
    }

    internal static string? NativeLibraryPath()
    {
        string fileName = OperatingSystem.IsWindows() ? "BouncyHsm.Pkcs11Lib.dll"
            : OperatingSystem.IsMacOS() ? "libBouncyHsm.Pkcs11Lib.dylib"
            : "BouncyHsm.Pkcs11Lib.so";
        string path = Path.Join(Settings.BouncyHsmDirectory, "runtimes", SoftHsmBackendFixture.GetRid(), "native", fileName);
        return File.Exists(path) ? path : null;
    }
}

/// <summary>xUnit collection definition for the BouncyHsm backend.</summary>
[CollectionDefinition("BouncyHsm")]
public sealed class BouncyHsmBackendCollection : ICollectionFixture<BouncyHsmBackendFixture> { }
