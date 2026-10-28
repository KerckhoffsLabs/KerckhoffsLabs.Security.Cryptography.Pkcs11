using System.Reflection;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// Backend fixture over Mozilla NSS softoken (<c>libsoftokn3.so</c>) — a third, fully independent
/// real PKCS#11 implementation alongside SoftHSM2 and opencryptoki. NSS is an unrelated crypto stack
/// (freebl, not OpenSSL), so a bug the wrapper and one backend happen to share is far less likely to
/// survive a round-trip here; it also uniquely exercises ChaCha20-Poly1305 and the SP800-108 counter
/// KDF, which neither CI real backend implements.
///
/// The library is built from the <c>vendor/nss</c> submodule and staged next to the test assembly by
/// the <c>BuildNss</c> MSBuild target; <see cref="Settings.NssLibraryPath"/> overrides the path for
/// one-off local debugging (e.g. pointing at a system <c>libsoftokn3.so</c>).
///
/// The fixture passes <see cref="Settings.NssModuleParameters"/> to <c>C_Initialize</c>: NSS before
/// 3.52 — the v2.40-only releases the <c>pkcs11-v240</c> CI leg runs — refuses to initialize without
/// a parameter string, and later releases accept the same one.
///
/// NSS softoken exposes a "NSS Generic Crypto Services" token whose <c>CKF_LOGIN_REQUIRED</c> flag is
/// clear and that has no user PIN — <c>C_Login</c> on it is rejected with
/// <see cref="CKR.CKR_USER_TYPE_INVALID"/>. The fixture therefore reports
/// <see cref="RequiresUserLogin"/> = <see langword="false"/>, so the shared test cases open it without
/// logging in. The token is write-protected, so only session (public) objects are used — which is all
/// the shared cases need (they create session keys with <c>CKA_TOKEN = false</c>).
/// </summary>
public sealed class NssBackendFixture : IPkcs11Backend, IDisposable
{
    public string LibraryPath { get; }
    public Pkcs11Library Library { get; } = null!;
    public NativeCULong SlotId { get; }

    // A login-not-required token has no SO/user PIN; the shared helpers never consult these because
    // RequiresUserLogin is false, but IPkcs11Backend requires them.
    public ReadOnlyMemory<byte> SoPin => ReadOnlyMemory<byte>.Empty;
    public ReadOnlyMemory<byte> UserPin => ReadOnlyMemory<byte>.Empty;

    public string TokenLabel { get; } = Settings.NssTokenLabel;

    /// <summary>NSS softoken's public token needs no login (see the type remarks).</summary>
    public bool RequiresUserLogin => false;

    /// <summary>Mechanisms the NSS token reports via <c>C_GetMechanismList</c>; empty when unavailable.</summary>
    public IReadOnlySet<CKM> SupportedMechanisms { get; } = new HashSet<CKM>();

    /// <summary>True when the NSS token's mechanism list includes <paramref name="mechanism"/>.</summary>
    public bool Supports(CKM mechanism) => SupportedMechanisms.Contains(mechanism);

    /// <summary>True when an NSS softoken library is configured (or built) and loadable.</summary>
    public static bool NssAvailable =>
        (Settings.NssLibraryPath is { } p && File.Exists(p)) || BuiltLibraryPath() is not null;

    // === NSS generic-token capability gates ================================
    // The login-not-required "NSS Generic Crypto Services" token is write-protected and its classic
    // AES-GCM params path deviates from the other backends. These static gates let the shared-case
    // wrappers skip the affected cases (SkipUnless) instead of failing, the same way the
    // mechanism-list gates skip unsupported mechanisms — so the boundary is visible, not hidden.

    /// <summary>NSS's generic crypto token is write-protected (<c>C_GenerateKey</c>/
    /// <c>C_GenerateKeyPair</c>/<c>C_CreateObject</c> of a token object return
    /// <see cref="CKR.CKR_TOKEN_WRITE_PROTECTED"/>), so shared helpers create session objects instead;
    /// the crypto is exercised identically. Cases that specifically require a persistent token object
    /// skip via <see cref="TokenObjectsAvailable"/>.</summary>
    public bool SupportsTokenObjects => false;

    /// <summary>Gate for cases that specifically need a writable token (persistent keys / token
    /// objects). Always false: NSS's generic token never persists token objects.</summary>
    public static bool TokenObjectsAvailable => false;

    /// <summary>True when the loaded softoken exposes the v3.0 message API (NSS 3.52 and later); false
    /// for the v2.40-only releases, and when NSS is unavailable.</summary>
    public bool SupportsMessageApi { get; }

    /// <summary>The softoken release, which NSS reports as each slot's <c>hardwareVersion</c>
    /// (3.131 for NSS 3.131); <c>0.0</c> when NSS is unavailable.</summary>
    public Version SoftokenVersion { get; } = new(0, 0);

    /// <summary>
    /// Skips the calling test unless the softoken is at least <paramref name="major"/>.<paramref name="minor"/>:
    /// for behaviour a release adds without changing its mechanism list, which the mechanism gates
    /// cannot see.
    /// </summary>
    public void RequireSoftoken(int major, int minor, string reason)
    {
        if (SoftokenVersion < new Version(major, minor))
            Assert.Skip($"NSS {SoftokenVersion} is older than {major}.{minor}: {reason}");
    }

    /// <summary>
    /// Skips the calling test unless AES-GCM can run on this softoken. <c>AesGcmPkcs11</c> uses the
    /// message API where the module has one and otherwise falls back to classic <c>C_EncryptInit</c>
    /// with <c>CK_GCM_PARAMS</c>, which NSS before 3.52 cannot read (see <see cref="RequireClassicAesGcm"/>):
    /// with no message API either, it fails that call with <see cref="CKR.CKR_HOST_MEMORY"/>.
    /// </summary>
    public void RequireAesGcm()
    {
        if (!SupportsMessageApi)
            Assert.Skip("NSS before 3.52 has no message API, and reads CK_GCM_PARAMS without ulIvBits, so AES-GCM does not work on it.");
    }

    /// <summary>
    /// Gate for cases that exercise the classic <c>CK_GCM_PARAMS</c> AES-GCM path. Which softoken releases
    /// accept it is only known once NSS is loaded, so such a case also calls
    /// <see cref="RequireClassicAesGcm"/>.
    /// </summary>
    public static bool ClassicAesGcmAvailable => NssAvailable;

    /// <summary>
    /// Skips the calling test unless AES-GCM works through classic <c>C_EncryptInit</c> +
    /// <c>CK_GCM_PARAMS</c> here: on NSS 3.52 and later, which the library binds through a v3.x interface
    /// and so sends <c>ulIvBits = ulIvLen * 8</c>, as they require. NSS before 3.52 reads a five-field
    /// struct without <c>ulIvBits</c>; the library sends it 0, which it takes as a NULL AAD pointer, and
    /// the call fails.
    /// </summary>
    public void RequireClassicAesGcm()
    {
        if (!Library.LowLevelLibrary!.IsBoundThroughV3Interface)
            Assert.Skip("NSS before 3.52 reads CK_GCM_PARAMS without ulIvBits, so classic AES-GCM does not work on it.");
    }

    /// <summary>True when classic AES-GCM can be fed in pieces through <c>C_EncryptUpdate</c> /
    /// <c>C_DecryptUpdate</c>. Always false, whatever the parameters: softoken's
    /// <c>sftk_CryptInit</c> marks a <see cref="CKM.CKM_AES_GCM"/> context single-part
    /// (<c>context->multi = PR_FALSE</c>), so the update calls fail with
    /// <see cref="CKR.CKR_OPERATION_NOT_INITIALIZED"/>.</summary>
    public static bool SupportsMultipartClassicAesGcm => false;

    /// <summary>Gate for cases that feed classic AES-GCM in pieces.</summary>
    public static bool MultipartClassicAesGcmAvailable => ClassicAesGcmAvailable && SupportsMultipartClassicAesGcm;

    /// <summary>True when the backend will derive a readable (extractable, non-sensitive) key whose
    /// value can be read back. NSS softoken refuses with <see cref="CKR.CKR_KEY_FUNCTION_NOT_PERMITTED"/>
    /// — it only derives non-extractable keys, a deliberate policy against exposing derived key
    /// material. The byte-returning KDF overloads need a readable derived key and so skip here; the
    /// on-token non-extractable derive still runs and exercises the KDF operation on NSS.</summary>
    public static bool SupportsExtractableDerive => false;

    /// <summary>Gate for KDF cases that read the derived key's value back to compare against the BCL.</summary>
    public static bool ExtractableDeriveAvailable => NssAvailable && SupportsExtractableDerive;

    /// <summary>True when <see cref="CKM.CKM_RC2_ECB"/> accepts the spec's <c>CK_RC2_PARAMS</c> (a bare
    /// effective-bits value). NSS softoken routes RC2-ECB and RC2-CBC through one code path that
    /// size-checks both against <c>CK_RC2_CBC_PARAMS</c>, so it rejects the spec-correct ECB params the
    /// wrapper sends with <see cref="CKR.CKR_MECHANISM_PARAM_INVALID"/>. RC2-CBC (which legitimately uses
    /// <c>CK_RC2_CBC_PARAMS</c>) works and is exercised; sending CBC params for ECB would be spec-wrong.</summary>
    public static bool SupportsRc2Ecb => false;

    /// <summary>Gate for the RC2-ECB round-trip case.</summary>
    public static bool Rc2EcbAvailable => NssAvailable && SupportsRc2Ecb;

    /// <summary>True when RSA PKCS#1 v1.5 <em>encryption</em> works through the buffer-growing path.
    /// NSS softoken's <c>RSA_EncryptBlock</c> returns a hard failure (mapped to
    /// <see cref="CKR.CKR_DEVICE_ERROR"/>) when the output buffer is smaller than the modulus, instead
    /// of <see cref="CKR.CKR_BUFFER_TOO_SMALL"/>, so the wrapper's grow-on-buffer-too-small sizing
    /// cannot drive it. RSA-OAEP encryption (length-checked differently by softoken) and every RSA
    /// sign/verify operation work; PKCS#1 v1.5 encryption is insecure (Bleichenbacher) and refused
    /// under Recommended anyway (available only via the AllowInsecure policy).</summary>
    public static bool SupportsRsaPkcs1Encrypt => false;

    /// <summary>Gate for the RSA PKCS#1 v1.5 encryption round-trip case.</summary>
    public static bool RsaPkcs1EncryptAvailable => NssAvailable && SupportsRsaPkcs1Encrypt;

    /// <summary>False while softoken refuses <c>C_VerifyInit</c> for <c>CKM_AES_CMAC</c> with
    /// <see cref="CKR.CKR_MECHANISM_INVALID"/>, although the mechanism advertises <c>CKF_VERIFY</c> and
    /// <c>C_SignInit</c> takes it (https://bugzilla.mozilla.org/show_bug.cgi?id=2075845). Signing works.
    /// NssQuirkTests.CmacVerify_QuirkStillPresent fails once it is fixed.</summary>
    public static bool SupportsCmacVerify => false;

    /// <summary>Gate for the AES-CMAC verify cases.</summary>
    public static bool CmacVerifyAvailable => NssAvailable && SupportsCmacVerify;

    /// <summary>False while softoken sets <c>CKA_LOCAL</c> to <see langword="false"/> on keys it generates with
    /// <c>C_GenerateKey</c> or <c>C_GenerateKeyPair</c>, where PKCS#11 has <see langword="true"/>
    /// (https://bugzilla.mozilla.org/show_bug.cgi?id=2075840). An imported key reports
    /// <see langword="false"/>, as it should. NssQuirkTests.GeneratedKeyLocal_QuirkStillPresent fails once it
    /// is fixed.</summary>
    public static bool SupportsLocalOnGeneratedKeys => false;

    /// <summary>Gate for the cases that check <c>CKA_LOCAL</c> on a generated key.</summary>
    public static bool LocalOnGeneratedKeysAvailable => NssAvailable && SupportsLocalOnGeneratedKeys;

    public NssBackendFixture()
    {
        string? libPath = Settings.NssLibraryPath ?? BuiltLibraryPath();
        if (libPath is null || !File.Exists(libPath))
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;
        Library = Pkcs11Library.Load(libPath, new Pkcs11LibraryOptions { ModuleParameters = Settings.NssModuleParameters });
        try
        {
            Pkcs11Slot found = Library.GetSlotList()
                .FirstOrDefault(s => s.GetTokenInfo().Label.TrimEnd() == TokenLabel)
                ?? throw new InvalidOperationException(
                    $"NSS token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)found.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(found.GetMechanismList());
            SupportsMessageApi = Library.LowLevelLibrary!.IsMessageApiSupported;
            SoftokenVersion = found.GetSlotInfo().HardwareVersion;
        }
        catch
        {
            Library.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        try { Library?.Dispose(); } catch { /* best-effort */ }
    }

    /// <summary>Path to the softoken staged next to the test assembly by the BuildNss target,
    /// or null when it is absent.</summary>
    internal static string? BuiltLibraryPath()
    {
        string asmDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? ".";
        string candidate = Path.Join(
            asmDir, "runtimes", SoftHsmBackendFixture.GetRid(), "native", "nss", "libsoftokn3.so");
        return File.Exists(candidate) ? candidate : null;
    }
}

/// <summary>xUnit collection definition for the NSS softoken backend.</summary>
[CollectionDefinition("Nss")]
public sealed class NssBackendCollection : ICollectionFixture<NssBackendFixture> { }
