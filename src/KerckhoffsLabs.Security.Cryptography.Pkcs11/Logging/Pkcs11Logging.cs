// Licensed under the MIT License

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;

/// <summary>
/// Static entry point for plugging an <see cref="ILoggerFactory"/> into the
/// PKCS#11 library. By default the factory is <see cref="NullLoggerFactory"/>,
/// so the library produces no log output. Integrators with a configured
/// <see cref="ILoggerFactory"/> (e.g. from a DI container) should call
/// <see cref="SetLoggerFactory(ILoggerFactory)"/> once at startup.
/// </summary>
/// <remarks>
/// <para>
/// All internal log calls flow through this class via <see cref="CreateLogger{T}"/>.
/// Replacing the factory affects every subsequent log call site, including those
/// captured into <c>static readonly</c> fields, because the loggers returned by
/// <see cref="ILoggerFactory.CreateLogger(string)"/> are typically thin wrappers
/// that re-dispatch through the factory on every call.
/// </para>
/// <para>
/// Loggers produced by this class respect the <c>{Name}</c> structured-logging
/// convention (named placeholders rather than positional <c>{0}</c>). Avoid
/// passing secret material into log calls — see <see cref="Security.SecurePin"/>
/// and <c>SecureBuffer</c>, both of which override <see cref="object.ToString"/>
/// to surface as a redacted marker rather than the underlying bytes.
/// </para>
/// </remarks>
public static class Pkcs11Logging
{
    private static ILoggerFactory _loggerFactory = NullLoggerFactory.Instance;

    /// <summary>
    /// Replaces the active <see cref="ILoggerFactory"/>. Passing <c>null</c>
    /// resets to <see cref="NullLoggerFactory.Instance"/>.
    /// </summary>
    /// <param name="loggerFactory">Logger factory to install, or <c>null</c> to disable logging.</param>
    public static void SetLoggerFactory(ILoggerFactory? loggerFactory)
    {
        _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
    }

    /// <summary>
    /// Creates an <see cref="ILogger"/> categorized for <typeparamref name="T"/>.
    /// </summary>
    internal static ILogger CreateLogger<T>() => _loggerFactory.CreateLogger<T>();

    /// <summary>
    /// Creates an <see cref="ILogger"/> categorized for the given type.
    /// </summary>
    internal static ILogger CreateLogger(Type type) => _loggerFactory.CreateLogger(type.FullName ?? type.Name);
}
