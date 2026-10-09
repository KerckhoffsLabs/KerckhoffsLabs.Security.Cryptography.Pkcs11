using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// Settings for <see cref="Pkcs11Library.Load(string, Pkcs11LibraryOptions)"/>: logging, and anything
/// module-specific the PKCS#11 module needs to initialize.
/// </summary>
/// <remarks>
/// Every setting defaults to the spec-standard behaviour, so an instance with nothing set initializes
/// a module exactly as <see cref="Pkcs11Library.Load(string, Microsoft.Extensions.Logging.ILoggerFactory?)"/> does.
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
    /// The string is passed as NUL-terminated UTF-8, and only for the duration of the
    /// <c>C_Initialize</c> call; the unmanaged copy is zeroed when the call returns, since some
    /// modules accept credentials here. It is never logged.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">The value contains a NUL character, which would silently truncate it.</exception>
    public string? ModuleParameters
    {
        get => _moduleParameters;
        init
        {
            if (value is not null && value.Contains('\0', StringComparison.Ordinal))
                throw new ArgumentException("Module parameters cannot contain a NUL character.", nameof(ModuleParameters));
            _moduleParameters = value;
        }
    }
}
