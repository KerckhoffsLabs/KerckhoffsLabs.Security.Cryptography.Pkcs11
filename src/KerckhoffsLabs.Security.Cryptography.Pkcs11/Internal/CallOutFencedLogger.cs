using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

/// <summary>
/// The session's logger: forwards to the consumer's, with every call into it run inside a
/// <see cref="Pkcs11SessionCore.CallOutScope"/>, so a sink that calls back into a session from inside a
/// secret read-back is judged as the caller it is, never as the library's read-back.
/// </summary>
internal sealed class CallOutFencedLogger(ILogger inner) : ILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull
    {
        using (Pkcs11SessionCore.CallOutScope.Enter())
            return inner.BeginScope(state);
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        using (Pkcs11SessionCore.CallOutScope.Enter())
            return inner.IsEnabled(logLevel);
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        using (Pkcs11SessionCore.CallOutScope.Enter())
            inner.Log(logLevel, eventId, state, exception, formatter);
    }
}
