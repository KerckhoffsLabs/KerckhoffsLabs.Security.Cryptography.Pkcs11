using System.Text;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Settings for <see cref="Pkcs11Library.Load(string, Pkcs11LibraryOptions?)"/> and
/// <see cref="Pkcs11Library.LoadStaticallyLinked(Pkcs11LibraryOptions?)"/>: logging, and anything
/// module-specific the PKCS#11 module needs to initialize.
/// </summary>
/// <remarks>
/// <para>
/// Every setting defaults to the spec-standard behaviour, so an instance with nothing set initializes
/// a module exactly as passing no options does.
/// </para>
/// <para>
/// How this maps onto <c>CK_C_INITIALIZE_ARGS</c>:
/// </para>
/// <list type="bullet">
/// <item><description>
/// No arguments at all (<c>pInitArgs = NULL_PTR</c>): <see cref="UseOsLocking"/> off with nothing
/// else set.
/// </description></item>
/// <item><description><c>pReserved</c>: <see cref="ModuleParameters"/>.</description></item>
/// <item><description><c>CKF_LIBRARY_CANT_CREATE_OS_THREADS</c>: <see cref="CantCreateOsThreads"/>.</description></item>
/// <item><description><c>CKF_OS_LOCKING_OK</c>: <see cref="UseOsLocking"/>.</description></item>
/// <item><description>
/// <c>CreateMutex</c>, <c>DestroyMutex</c>, <c>LockMutex</c>, <c>UnlockMutex</c>: deliberately
/// unsupported, always <c>NULL_PTR</c>. Those callbacks would be managed code the module calls back
/// into, from its own threads, for the life of the module; OS locking or the library's own
/// serialization gives the same guarantee without that.
/// </description></item>
/// </list>
/// </remarks>
public sealed class Pkcs11LibraryOptions
{
    private readonly string? _moduleParameters;

    /// <summary>
    /// Logger factory for the library and every <see cref="Pkcs11Slot"/>/<c>Pkcs11Session</c> it
    /// produces, or <see langword="null"/> (the default) for no logging.
    /// </summary>
    public ILoggerFactory? LoggerFactory { get; init; }

    /// <summary>
    /// Whether <c>C_Initialize</c> asks the module to use OS locking (<c>CKF_OS_LOCKING_OK</c>), so it
    /// can be called from several threads at once. Defaults to <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// On, the library asks for OS locking first, and if the module refuses with <c>CKR_CANT_LOCK</c>,
    /// initializes it again without. Off, it initializes without from the start: with
    /// <c>pInitArgs = NULL_PTR</c> when nothing else is set, which the standard requires every module
    /// to accept, and otherwise with arguments that carry the other settings but neither
    /// <c>CKF_OS_LOCKING_OK</c> nor mutex callbacks.
    /// </para>
    /// <para>
    /// Without OS locking, the library serializes every call into the module (see
    /// <see cref="Pkcs11Library.SupportsConcurrentAccess"/>). Turn it off for a module that rejects
    /// <c>CKF_OS_LOCKING_OK</c> with something other than <c>CKR_CANT_LOCK</c>, which would otherwise
    /// fail to load, or one that misbehaves under it.
    /// </para>
    /// </remarks>
    public bool UseOsLocking { get; init; } = true;

    /// <summary>
    /// Sets <c>CKF_LIBRARY_CANT_CREATE_OS_THREADS</c> in <c>C_Initialize</c>: declares that the module
    /// must not create threads of its own, for a host where that is not allowed. Defaults to
    /// <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// A module that cannot work without its own threads refuses to initialize, with
    /// <c>CKR_NEED_TO_CREATE_THREADS</c>.
    /// </remarks>
    public bool CantCreateOsThreads { get; init; }

    /// <summary>
    /// A module-specific configuration string passed to <c>C_Initialize</c> in the
    /// <c>pReserved</c> field of <c>CK_C_INITIALIZE_ARGS</c>, or <see langword="null"/> (the
    /// default) to leave that field <c>NULL_PTR</c> as the standard requires.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The PKCS#11 standard reserves <c>pReserved</c> and requires it to be <c>NULL_PTR</c>; some
    /// modules nevertheless read their configuration from it, and refuse to initialize without it.
    /// Mozilla NSS softoken before 3.52 is one: it returns <c>CKR_ARGUMENTS_BAD</c> unless given its
    /// parameter string, e.g.
    /// <c>configdir='' certPrefix='' keyPrefix='' secmod='' flags=readOnly,noCertDB,noModDB,forceOpen</c>.
    /// Set this only for a module whose documentation asks for it: a module that follows the
    /// standard may reject a non-null <c>pReserved</c> with <c>CKR_ARGUMENTS_BAD</c>.
    /// </para>
    /// <para>
    /// <c>pReserved</c> is a <c>CK_VOID_PTR</c>, so what it points to is the vendor's to define; this
    /// setting covers the modules that read a C string there, as NSS does. One that expects a pointer
    /// to a structure or a binary block cannot be configured through it.
    /// </para>
    /// <para>
    /// The string is passed as NUL-terminated UTF-8, and only for the duration of the
    /// <c>C_Initialize</c> call; the unmanaged copy is zeroed when the call returns, since some
    /// modules accept credentials here. It is never logged.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// The value contains a NUL character, which would silently truncate it, or is not valid UTF-16 (a
    /// lone surrogate), so cannot be encoded as UTF-8 without altering it.
    /// </exception>
    public string? ModuleParameters
    {
        get => _moduleParameters;
        init
        {
            if (value is not null)
            {
                if (value.Contains('\0', StringComparison.Ordinal))
                    throw new ArgumentException("Module parameters cannot contain a NUL character.", nameof(ModuleParameters));
                try
                {
                    _ = StrictUtf8.GetByteCount(value);
                }
                catch (EncoderFallbackException ex)
                {
                    throw new ArgumentException("Module parameters are not valid UTF-16 and cannot be encoded as UTF-8.", nameof(ModuleParameters), ex);
                }
            }
            _moduleParameters = value;
        }
    }

    // Strict UTF-8: a lone surrogate is refused rather than silently replaced with U+FFFD, which would
    // hand the module a configuration string different from the one the caller wrote.
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
}
