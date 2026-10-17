using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture for BouncyHsm (harrison314/BouncyHsm): a PKCS#11 v3.x soft HSM whose
/// native client forwards every call over TCP to a .NET server built on BouncyCastle. It is a sixth,
/// independent implementation alongside the mock, SoftHSM2, NSS, Kryoptic and opencryptoki. Supported on
/// Linux x64 only; elsewhere <see cref="BouncyHsmAvailable"/> is false and its tests skip.
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

    /// <summary>True on Linux when a BouncyHsm server and a native client for this RID are staged. Never starts a process.</summary>
    public static bool BouncyHsmAvailable =>
        OperatingSystem.IsLinux() && ServerAssemblyPath() is not null && NativeLibraryPath() is not null;

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

    /// <summary>
    /// False while harrison314/BouncyHsm#118 is open: raw <c>CKM_CHACHA20</c> takes only a zero
    /// <c>blockCounter</c> in <c>CK_CHACHA20_PARAMS</c> and refuses any other at init with
    /// <c>CKR_GENERAL_ERROR</c>. BouncyHsmQuirkTests.NonZeroChaCha20Counter_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsNonZeroChaCha20Counter = false;

    /// <summary>
    /// False while harrison314/BouncyHsm#119 is open: a <c>CKM_HKDF_DERIVE</c> with <c>bExpand</c> false still
    /// runs the expand stage, so an extract-only derivation gives HKDF-Expand(PRK, empty info) instead of the
    /// PRK, against PKCS#11 v3.0 §2.43. BouncyHsmQuirkTests.HkdfExtractOnly_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmHonoursHkdfExtractOnly = false;

    /// <summary>
    /// False while harrison314/BouncyHsm#120 is open: its client requires a <c>CK_SP800_108_COUNTER_FORMAT</c> on the SP 800-108 iteration
    /// variable in every mode: in feedback and double-pipeline mode PKCS#11 v3.0 requires <c>pValue = NULL_PTR</c>,
    /// <c>ulValueLen = 0</c>, which it refuses with <c>CKR_MECHANISM_INVALID</c> (<c>bouncy-pkcs11-utils.c</c> in
    /// v2.3.3). Given a format instead, its server cuts the chaining value to the format's width, so the result is
    /// not SP 800-108's either. BouncyHsmQuirkTests.Sp800108NullIterationVariable_QuirkStillPresent fails once it
    /// is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsNullSp800108IterationVariable = false;

    /// <summary>Gate for empty-input digest and MAC cases: see <see cref="BouncyHsmAcceptsEmptyInput"/>.</summary>
    public static bool EmptyDigestAndMacAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptyInput;

    /// <summary>Gate for cases that verify a tampered RSA-PSS signature: see <see cref="BouncyHsmRejectsOutOfRangeSignatures"/>.</summary>
    public static bool OutOfRangeSignatureRejectionAvailable => BouncyHsmAvailable && BouncyHsmRejectsOutOfRangeSignatures;

    /// <summary>Gate for raw ChaCha20 cases that start at a non-zero block counter: see <see cref="BouncyHsmAcceptsNonZeroChaCha20Counter"/>.</summary>
    public static bool NonZeroChaCha20CounterAvailable => BouncyHsmAvailable && BouncyHsmAcceptsNonZeroChaCha20Counter;

    /// <summary>Gate for extract-only HKDF cases: see <see cref="BouncyHsmHonoursHkdfExtractOnly"/>.</summary>
    public static bool HkdfExtractOnlyAvailable => BouncyHsmAvailable && BouncyHsmHonoursHkdfExtractOnly;

    /// <summary>Gate for SP 800-108 feedback and double-pipeline cases: see <see cref="BouncyHsmAcceptsNullSp800108IterationVariable"/>.</summary>
    public static bool ChainedSp800108KdfAvailable => BouncyHsmAvailable && BouncyHsmAcceptsNullSp800108IterationVariable;

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
            // Library.Dispose logs a failed C_Finalize rather than throwing, so the server is always reached.
            Library?.Dispose();
            _server.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Library?.Dispose();
        _server?.Dispose();
    }

    internal static string? ServerAssemblyPath()
    {
        string path = Path.Join(Settings.BouncyHsmDirectory, "server", "BouncyHsm.dll");
        return File.Exists(path) ? path : null;
    }

    internal static string? NativeLibraryPath()
    {
        string path = Path.Join(Settings.BouncyHsmDirectory, "runtimes", SoftHsmBackendFixture.GetRid(), "native", "BouncyHsm.Pkcs11Lib.so");
        return File.Exists(path) ? path : null;
    }
}

/// <summary>xUnit collection definition for the BouncyHsm backend.</summary>
[CollectionDefinition("BouncyHsm")]
public sealed class BouncyHsmBackendCollection : ICollectionFixture<BouncyHsmBackendFixture> { }
