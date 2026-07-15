using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

/// <summary>
/// Abstraction over a backing PKCS#11 module (pkcs11-mock or SoftHSM2). Tests
/// depend on this rather than on a concrete fixture, so the same test runs
/// against either backend via the xUnit <c>[Collection]</c> mechanism.
/// </summary>
public interface IPkcs11Backend
{
    /// <summary>Absolute path to the loaded shared library.</summary>
    string LibraryPath { get; }

    /// <summary>The shared <see cref="Pkcs11Library"/> instance for the backend.</summary>
    Pkcs11Library Library { get; }

    /// <summary>Slot id of a slot containing an initialized token.</summary>
    NativeCULong SlotId { get; }

    /// <summary>SO PIN for the fixture's token (raw bytes, immutable view).</summary>
    ReadOnlyMemory<byte> SoPin { get; }

    /// <summary>Normal-user PIN for the fixture's token (raw bytes, immutable view).</summary>
    ReadOnlyMemory<byte> UserPin { get; }

    /// <summary>Label of the fixture's token.</summary>
    string TokenLabel { get; }

    /// <summary>Mechanisms the loaded token advertises (from <c>C_GetMechanismList</c>). Lets shared,
    /// backend-agnostic test cases gate per mechanism and skip where a backend lacks support.</summary>
    IReadOnlySet<CKM> SupportedMechanisms { get; }

    /// <summary>True if the token advertises <paramref name="mechanism"/>.</summary>
    bool Supports(CKM mechanism);

    /// <summary>True when the backend can persist token objects (<c>CKA_TOKEN = true</c>). Default
    /// <see langword="true"/>; a write-protected token (NSS softoken's generic crypto services)
    /// overrides to <see langword="false"/> so shared helpers create session objects, which the same
    /// crypto exercises identically, instead of hitting <see cref="CKR.CKR_TOKEN_WRITE_PROTECTED"/>.</summary>
    bool SupportsTokenObjects => true;

    /// <summary>True when the fixture's token requires a normal-user <c>C_Login</c> before
    /// private/session crypto — the usual case. A login-not-required token (NSS softoken's public
    /// crypto services, whose token has <c>CKF_LOGIN_REQUIRED</c> clear and rejects <c>C_Login</c>
    /// with <see cref="CKR.CKR_USER_TYPE_INVALID"/>) sets this <see langword="false"/>, so the shared
    /// helpers open without logging in. Centralizing the toggle here lets backend-agnostic test cases
    /// run unchanged against both auth models.</summary>
    bool RequiresUserLogin => true;

    /// <summary>Opens a workspace over the fixture's token using the backend's authentication model:
    /// a normal-user login when <see cref="RequiresUserLogin"/> is set, otherwise no login. Shared,
    /// backend-agnostic test cases call this instead of hard-coding the login path.</summary>
    Pkcs11Workspace OpenWorkspace() =>
        RequiresUserLogin
            ? Library.OpenWorkspace(TokenLabel, CKU.CKU_USER, new SecurePin(UserPin.Span))
            : Library.OpenWorkspaceWithoutLogin(TokenLabel);

    /// <summary>True if the backend can generate and operate ML-DSA (FIPS 204) keys. Defaults to the
    /// advertised <see cref="CKM.CKM_ML_DSA"/>; SoftHSM overrides this with a build marker because the
    /// real capability depends on the OpenSSL it was built against, not just the mechanism list.</summary>
    bool SupportsMlDsa => Supports(CKM.CKM_ML_DSA);

    /// <summary>True if the backend can generate and operate ML-KEM (FIPS 203) keys. Defaults to the
    /// advertised <see cref="CKM.CKM_ML_KEM"/>; SoftHSM overrides this with a build marker.</summary>
    bool SupportsMlKem => Supports(CKM.CKM_ML_KEM);

    /// <summary>True if the backend can generate and operate SLH-DSA (FIPS 205) keys. Defaults to the
    /// advertised <see cref="CKM.CKM_SLH_DSA"/>; SoftHSM overrides this with a build marker.</summary>
    bool SupportsSlhDsa => Supports(CKM.CKM_SLH_DSA);

    /// <summary>The <see cref="CKR"/> an AEAD decryption (AES-GCM/CCM, ChaCha20-Poly1305) returns when
    /// the authentication tag check fails, for backends that return a stable, specific code. When set,
    /// AEAD authenticity tests assert it exactly; <see langword="null"/> (the default) means the code is
    /// not pinned for this backend, so those tests only assert that some <c>Pkcs11Exception</c> is
    /// thrown (forgery rejected). SoftHSM returns <see cref="CKR.CKR_ENCRYPTED_DATA_INVALID"/>;
    /// opencryptoki's code is not pinned here.</summary>
    CKR? AeadAuthFailureCode => null;
}
