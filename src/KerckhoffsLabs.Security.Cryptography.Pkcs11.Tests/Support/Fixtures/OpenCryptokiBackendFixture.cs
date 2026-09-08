using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// Backend fixture for a system-installed opencryptoki soft token — a second, independent real
/// PKCS#11 implementation alongside SoftHSM2. Running the same operations against two unrelated
/// modules catches a bug that SoftHSM and the wrapper happen to share (a mis-encoding that survives
/// a SoftHSM-only round-trip).
///
/// opencryptoki is not built from a submodule: it is system-installed and its token is provisioned
/// out-of-band (daemon + <c>pkcsconf</c>, done in CI), so this fixture only opens an already-
/// initialized token. It is inert — every dependent test skips — unless
/// <see cref="Settings.OpenCryptokiLibraryPath"/> points at a loadable library.
/// </summary>
public sealed class OpenCryptokiBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.OpenCryptokiSoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.OpenCryptokiUserPin);
    public string TokenLabel { get; } = Settings.OpenCryptokiTokenLabel;

    /// <summary>Mechanisms the opencryptoki token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the opencryptoki token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True when an opencryptoki library has been configured and is loadable.</summary>
    public static bool OpenCryptokiAvailable =>
        Settings.OpenCryptokiLibraryPath is { } p && File.Exists(p);

    public OpenCryptokiBackendFixture()
    {
        string? libPath = Settings.OpenCryptokiLibraryPath;
        if (libPath is null || !File.Exists(libPath))
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;
        Library = new Pkcs11Library(libPath);
        try
        {
            Pkcs11Slot found = Library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label == TokenLabel)
                ?? throw new InvalidOperationException(
                    $"opencryptoki token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)found.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(found.GetMechanismList());
        }
        catch
        {
            Library.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens a workspace, retrying a handful of times when <c>C_Login</c> fails with
    /// <see cref="CKR.CKR_GENERAL_ERROR"/>. Under CI load, opencryptoki's soft-token STDLL
    /// occasionally returns this transiently from its shared-memory session bookkeeping after
    /// hundreds of rapid login/logout cycles in the same run — a token-side flake, not something
    /// a caller did wrong, and PKCS#11 v3.2 §5.1 lists CKR_GENERAL_ERROR as a code a token may
    /// return when "some horrible, unrecoverable error has occurred" without requiring that it be
    /// permanent. SoftHSM and NSS don't exhibit this, so the retry lives here rather than in the
    /// shared <see cref="IPkcs11Backend.OpenWorkspace"/> default.
    /// </summary>
    public Pkcs11Workspace OpenWorkspace()
    {
        const int maxAttempts = 3;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return Library.OpenWorkspace(TokenLabel, CKU.CKU_USER, new SecurePin(UserPin.Span));
            }
            catch (Pkcs11Exception ex) when (ex.ReturnValue == CKR.CKR_GENERAL_ERROR && attempt < maxAttempts)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(200 * attempt));
            }
        }
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { /* best-effort */ }
    }
}

/// <summary>xUnit collection definition for the opencryptoki backend.</summary>
[CollectionDefinition("OpenCryptoki")]
public sealed class OpenCryptokiBackendCollection : ICollectionFixture<OpenCryptokiBackendFixture> { }
