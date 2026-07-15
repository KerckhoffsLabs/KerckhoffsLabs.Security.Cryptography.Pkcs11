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
    // wrappers skip the affected cases (ConditionalFact) instead of failing, the same way the
    // mechanism-list gates skip unsupported mechanisms — so the boundary is visible, not hidden.

    /// <summary>True when the backend can persist token objects. NSS's generic crypto token is
    /// write-protected (<c>C_GenerateKey</c>/<c>C_GenerateKeyPair</c>/<c>C_CreateObject</c> of a token
    /// object return <see cref="CKR.CKR_TOKEN_WRITE_PROTECTED"/>), so persistent-key and token-object
    /// cases do not apply — session objects, which every crypto case here uses, still work.</summary>
    public static bool SupportsTokenObjects => false;

    /// <summary>True when AES-GCM works through the classic <c>C_EncryptInit</c> + <c>CK_GCM_PARAMS</c>
    /// path. NSS softoken rejects that path's spec-legal <c>ulIvBits = 0</c> with
    /// <see cref="CKR.CKR_MECHANISM_PARAM_INVALID"/> (setting it non-zero breaks SoftHSM, so the shared
    /// params keep 0); GCM against NSS instead goes through the message-based <c>AesGcmPkcs11</c>
    /// façade, which is covered by the AEAD façade tests.</summary>
    public static bool SupportsClassicAesGcm => false;

    /// <summary>True when EdDSA works the way the shared pure-Ed25519 case drives it (a bare
    /// <see cref="CKM.CKM_EDDSA"/> with no parameter). NSS 3.125+ advertises <c>CKM_EDDSA</c>, so the
    /// mechanism-list gate would let the case run, but NSS's softoken requires a <c>CK_EDDSA_PARAMS</c>
    /// and rejects a bare sign with <see cref="CKR.CKR_ARGUMENTS_BAD"/>; SoftHSM accepts the bare form.
    /// EdDSA-with-params is a distinct mechanism contract not modelled here, so those cases skip.</summary>
    public static bool SupportsEdDsa => false;

    /// <summary>Gate for cases that need a writable token (persistent keys / token objects).</summary>
    public static bool TokenObjectsAvailable => NssAvailable && SupportsTokenObjects;

    /// <summary>Gate for cases that exercise the classic <c>CK_GCM_PARAMS</c> AES-GCM path.</summary>
    public static bool ClassicAesGcmAvailable => NssAvailable && SupportsClassicAesGcm;

    /// <summary>Gate for the shared bare-parameter EdDSA cases.</summary>
    public static bool EdDsaAvailable => NssAvailable && SupportsEdDsa;

    public NssBackendFixture()
    {
        string? libPath = Settings.NssLibraryPath ?? BuiltLibraryPath();
        if (libPath is null || !File.Exists(libPath))
        {
            LibraryPath = string.Empty;
            return;
        }

        LibraryPath = libPath;
        Library = new Pkcs11Library(libPath);
        try
        {
            Pkcs11Slot found = Library.GetSlotList()
                .FirstOrDefault(s => s.GetTokenInfo().Label.TrimEnd() == TokenLabel)
                ?? throw new InvalidOperationException(
                    $"NSS token '{TokenLabel}' did not appear in the slot list.");
            SlotId = (NativeCULong)found.SlotId.Value;
            SupportedMechanisms = new HashSet<CKM>(found.GetMechanismList());
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
        string candidate = Path.Combine(
            asmDir, "runtimes", SoftHsmBackendFixture.GetRid(), "native", "nss", "libsoftokn3.so");
        return File.Exists(candidate) ? candidate : null;
    }
}

/// <summary>xUnit collection definition for the NSS softoken backend.</summary>
[CollectionDefinition("Nss")]
public sealed class NssBackendCollection : ICollectionFixture<NssBackendFixture> { }
