using System.Reflection;
using System.Text;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// xUnit collection fixture wrapping wolfPKCS11 — another fully independent real PKCS#11 implementation
/// alongside SoftHSM2, opencryptoki, NSS softoken, Kryoptic, BouncyHsm, Craton HSM and FreeHSM. A C
/// PKCS#11 v3.2 module on wolfCrypt, with ML-KEM and ML-DSA, used here with its own file-based software
/// token (not its wolfTPM backend).
///
/// Uses the library built from the vendor/wolfpkcs11 and vendor/wolfssl submodules and placed next to the
/// test assembly by the BuildWolfPkcs11 MSBuild target; <see cref="Settings.WolfPkcs11LibraryPath"/> may
/// override the path for local debugging. Linux-only for now (see build-wolfpkcs11.sh).
///
/// Like FreeHSM, wolfPKCS11 implements <c>C_InitToken</c>/<c>C_InitPIN</c>, so the token is provisioned
/// through the library under test. Its token store goes to a fresh owner-only temporary directory named by
/// <c>WOLFPKCS11_TOKEN_PATH</c>, so every run starts from a factory-state token, leaves nothing behind and
/// never touches the default <c>~/.wolfPKCS11</c>.
/// </summary>
public sealed class WolfPkcs11BackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }
    public ReadOnlyMemory<byte> SoPin { get; } = Encoding.UTF8.GetBytes(Settings.SoPin);
    public ReadOnlyMemory<byte> UserPin { get; } = Encoding.UTF8.GetBytes(Settings.UserPin);
    public string TokenLabel { get; } = "phase1-test-token";

    /// <summary>The set of <see cref="CKM"/> mechanisms exposed by the token (from <c>C_GetMechanismList</c>).
    /// Populated at fixture construction. Empty when wolfPKCS11 is unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when <paramref name="mechanism"/> appears in the token's mechanism list.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>The directory named by <c>WOLFPKCS11_TOKEN_PATH</c>, where the module keeps its token.</summary>
    internal string TokenDirectory { get; } = string.Empty;

    public static bool WolfPkcs11Available =>
        (Settings.WolfPkcs11LibraryPath is { } p && File.Exists(p)) ||
        BuiltLibraryPath() is not null;

    public WolfPkcs11BackendFixture()
    {
        string? libPath = Settings.WolfPkcs11LibraryPath ?? BuiltLibraryPath();

        if (libPath is null)
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;

        // Owner-only by construction (CreateTempSubdirectory makes it 0700).
        TokenDirectory = Directory.CreateTempSubdirectory("kl-wolfpkcs11-").FullName;

        // libwolfpkcs11.so reads it through getenv() when it opens its store; as for Kryoptic, .NET's
        // Environment.SetEnvironmentVariable does not reach native getenv() on Linux, so setenv() too.
        SetEnv("WOLFPKCS11_TOKEN_PATH", TokenDirectory);

        Library = Pkcs11Library.Load(LibraryPath);
        try
        {
            Pkcs11Slot slot = Library.GetSlotList(tokenPresent: false)
                .FirstOrDefault(s => !s.GetTokenInfo().TokenFlags.TokenInitialized)
                ?? throw new InvalidOperationException("wolfPKCS11 listed no slot with an uninitialized token.");

            slot.InitTokenWithPin(new SecurePin(SoPin.Span), TokenLabel);

            using (Pkcs11Session so = Library.OpenSessionWithPin(TokenLabel, CKU.CKU_SO, new SecurePin(SoPin.Span)))
            {
                so.InitPinWithPin(new SecurePin(UserPin.Span));
            }

            SlotId = (NativeCULong)slot.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(slot.GetMechanismList());
        }
        catch (Exception e) when (e is Pkcs11Exception or InvalidOperationException)
        {
            Library.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        Library?.Dispose();
        try
        {
            if (TokenDirectory.Length > 0)
                Directory.Delete(TokenDirectory, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort: a leftover directory under the temp path holds only throwaway test state.
        }
    }

    private static void SetEnv(string name, string value)
    {
        Environment.SetEnvironmentVariable(name, value);
        KryopticBackendFixture.SetNativeEnv(name, value);
    }

    internal static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string candidate = Path.Join(asmDir, "runtimes", KryopticBackendFixture.GetRid(), "native", "libwolfpkcs11.so");
        return File.Exists(candidate) ? candidate : null;
    }
}

/// <summary>xUnit collection definition for the wolfPKCS11 backend.</summary>
[CollectionDefinition("WolfPkcs11")]
public sealed class WolfPkcs11BackendCollection : ICollectionFixture<WolfPkcs11BackendFixture>
{ }
