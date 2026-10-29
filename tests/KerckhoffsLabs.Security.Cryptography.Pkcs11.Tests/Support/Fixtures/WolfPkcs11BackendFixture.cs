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

    // What wolfPKCS11 at the vendored commit (v2.2.0) does differently from PKCS#11 v3.2 that the shared
    // cases run into. Each flag is false while it stands, a gate or a wrapper check skips the cases it
    // breaks, and the matching WolfPkcs11QuirkTests tripwire fails once it is fixed: set the flag to true
    // then and delete the tripwire.

    /// <summary>
    /// False while <c>C_DeriveKey</c> overrides the template's <c>CKA_SENSITIVE</c> and <c>CKA_EXTRACTABLE</c>
    /// from the base key: a sensitive base gives a sensitive key and a non-extractable base a non-extractable
    /// one, whatever the template asks, so the value of an ECDH secret or an HKDF output cannot be read back.
    /// For <c>CKM_ECDH1_DERIVE</c> (§6.3.17) and <c>CKM_HKDF_DERIVE</c> (§6.62.3) the template may set either
    /// value; the base key decides only <c>CKA_ALWAYS_SENSITIVE</c> and <c>CKA_NEVER_EXTRACTABLE</c>.
    /// </summary>
    public const bool WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity = false;

    /// <summary>
    /// False while RSA-OAEP refuses an empty message: <c>C_Encrypt</c> of zero bytes gives
    /// <c>CKR_FUNCTION_FAILED</c> and <c>C_Decrypt</c> of another implementation's ciphertext of it
    /// <c>CKR_ENCRYPTED_DATA_INVALID</c>, though RFC 8017 §7.1 allows any length up to k - 2hLen - 2.
    /// </summary>
    public const bool WolfPkcs11AcceptsEmptyOaepMessage = false;

    /// <summary>
    /// False while <c>C_Verify</c> answers a malformed or out-of-range signature with <c>CKR_FUNCTION_FAILED</c>
    /// instead of <c>CKR_SIGNATURE_INVALID</c>, so the caller cannot tell a bad signature from a failing token:
    /// every altered PKCS#1 v1.5 RSA signature, an RSA-PSS one at or above the modulus, an ECDSA P-521 one
    /// whose r or s has a bit above the 521st set, and an ML-DSA one whose hint encoding is malformed (FIPS 204
    /// §7.3 rejects it like any other invalid signature). Correctly encoded wrong signatures get
    /// <c>CKR_SIGNATURE_INVALID</c>. Which one a one-bit flip gives depends on the bit and the signature, so
    /// the cases that alter a signature would fail at random.
    /// </summary>
    public const bool WolfPkcs11RejectsMalformedSignatures = false;

    /// <summary>
    /// False while <c>CKM_RSA_PKCS_KEY_PAIR_GEN</c> advertises 1024 bits as its minimum (a constant in
    /// <c>src/slot.c</c>) but fails to make a 1024-bit key with <c>CKR_FUNCTION_FAILED</c>: wolfSSL's default
    /// <c>RSA_MIN_SIZE</c> is 2048.
    /// </summary>
    public const bool WolfPkcs11GeneratesItsMinimumRsaKeySize = false;

    /// <summary>Gate for cases that read back a derived key: see <see cref="WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity"/>.</summary>
    public static bool DerivedKeyReadbackAvailable => WolfPkcs11Available && WolfPkcs11DerivedKeysTakeTheTemplatesSensitivity;

    /// <summary>Gate for cases that verify an altered signature: see <see cref="WolfPkcs11RejectsMalformedSignatures"/>.</summary>
    public static bool MalformedSignatureRejectionAvailable => WolfPkcs11Available && WolfPkcs11RejectsMalformedSignatures;

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
