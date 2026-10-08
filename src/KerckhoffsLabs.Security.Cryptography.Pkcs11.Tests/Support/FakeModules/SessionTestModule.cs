using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

/// <summary>
/// A <see cref="FakeModule"/> for tests that drive a <see cref="Pkcs11Session"/> directly: it accepts
/// <c>C_CloseSession</c>, and <see cref="CreateSession"/> opens a session over the module through the real
/// loader and wrappers. A test overrides only the functions its scenario calls; any other is absent, so the
/// session sees <c>CKR_FUNCTION_NOT_SUPPORTED</c> for it.
/// </summary>
/// <remarks>
/// Dispose the session before the module (declare the module first): the module disposes the library the
/// session calls through.
/// </remarks>
internal abstract class SessionTestModule : FakeModule
{
    private LowLevelPkcs11Library? _lowLevel;

    /// <summary>This module bound through the real loader, once; disposed with the module.</summary>
    public LowLevelPkcs11Library LowLevel => _lowLevel ??= LoadLowLevel();

    /// <summary>A session on this module, as the library would hand out after <c>C_OpenSession</c>.</summary>
    /// <param name="sessionId">The session's handle; a fresh one that routes to this module when omitted.</param>
    /// <param name="loggerFactory">Passed to the session.</param>
    /// <param name="policy">The session's policy; <see cref="CryptoPolicy.SecureOnly"/> when omitted.</param>
    public Pkcs11Session CreateSession(ulong? sessionId = null, ILoggerFactory? loggerFactory = null, ICryptoPolicy? policy = null)
        => new(LowLevel, sessionId ?? (ulong)NewSessionHandle(), loggerFactory, policy);

    protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

    protected override void Disposing() => _lowLevel?.Dispose();
}
