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
    /// False while the server refuses to digest empty data: the fix for harrison314/BouncyHsm#115 lets
    /// <c>ulDataLen == 0</c> through the client and the server signs and verifies empty data, but
    /// <c>DigestSessionState.Final</c> still answers a digest of no data with <c>CKR_DATA_LEN_RANGE</c>. Not yet
    /// reported upstream. BouncyHsmQuirkTests.EmptyDigest_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsEmptyDigest = false;

    /// <summary>
    /// False while the native client refuses <c>ulSignatureLen == 0</c> in <c>C_Verify</c> with
    /// <c>CKR_ARGUMENTS_BAD</c> (<c>bouncy-pkcs11.c</c>, as does <c>C_VerifyFinal</c>), where an empty signature is simply invalid. Not yet
    /// reported upstream. BouncyHsmQuirkTests.EmptySignature_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmAcceptsEmptySignature = false;

    /// <summary>
    /// False while <c>CKM_SP800_108_DOUBLE_PIPELINE_KDF</c> runs the A chain one PRF ahead: <c>Sp800_108DoublePipelineKdf</c>
    /// computes A(1) = PRF(fixed input) as SP 800-108 §5.3 does, then applies the PRF again before the first block, so
    /// block i is keyed on A(i+1). Feedback mode is not affected. Not yet reported upstream.
    /// BouncyHsmQuirkTests.Sp800108DoublePipeline_QuirkStillPresent fails once it is fixed.
    /// </summary>
    public const bool BouncyHsmDoublePipelineMatchesSp800108 = false;

    /// <summary>
    /// False while <c>C_Logout</c> leaves the application's private session objects in place: a new login finds
    /// them again under their old handles, where PKCS#11 v3.2 §5.6.10 destroys them. While nobody is logged in,
    /// the handle of a private object (session or token) answers <c>C_GetAttributeValue</c> with
    /// <c>CKR_USER_NOT_LOGGED_IN</c>, a code §5.7.5 does not list for it, rather than <c>CKR_OBJECT_HANDLE_INVALID</c>.
    /// Not yet reported upstream. BouncyHsmQuirkTests.PrivateSessionObjectAfterLogout_QuirkStillPresent fails once
    /// it is fixed.
    /// </summary>
    public const bool BouncyHsmDestroysPrivateSessionObjectsOnLogout = false;

    /// <summary>Gate for the C_Logout handle case: see <see cref="BouncyHsmDestroysPrivateSessionObjectsOnLogout"/>.</summary>
    public static bool LogoutInvalidationAvailable => BouncyHsmAvailable && BouncyHsmDestroysPrivateSessionObjectsOnLogout;

    /// <summary>Gate for empty-input digest cases: see <see cref="BouncyHsmAcceptsEmptyDigest"/>.</summary>
    public static bool EmptyDigestAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptyDigest;

    /// <summary>Gate for cases that verify an empty RSA signature: see <see cref="BouncyHsmAcceptsEmptySignature"/>.</summary>
    public static bool WrongLengthRsaSignatureRejectionAvailable => BouncyHsmAvailable && BouncyHsmAcceptsEmptySignature;

    /// <summary>Gate for SP 800-108 double-pipeline cases: see <see cref="BouncyHsmDoublePipelineMatchesSp800108"/>.</summary>
    public static bool Sp800108DoublePipelineAvailable => BouncyHsmAvailable && BouncyHsmDoublePipelineMatchesSp800108;

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
