using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Logging;

/// <summary>Test <see cref="ILogger"/> that records each emitted entry (level, id, rendered text).</summary>
internal sealed class CapturingLogger : ILogger
{
    public sealed record Entry(LogLevel Level, EventId EventId, string Message);

    public List<Entry> Entries { get; } = [];

    /// <summary>Controls <see cref="IsEnabled"/> so tests can exercise the level-disabled path.</summary>
    public bool Enabled { get; set; } = true;

    IDisposable? ILogger.BeginScope<TState>(TState state) => null;

    public bool IsEnabled(LogLevel logLevel) => Enabled;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
        => Entries.Add(new Entry(logLevel, eventId, formatter(state, exception)));
}

/// <summary>Test <see cref="ILoggerFactory"/> that always returns <paramref name="logger"/> and records the last category.</summary>
internal sealed class CapturingLoggerFactory(ILogger logger) : ILoggerFactory
{
    public string? LastCategory { get; private set; }

    public ILogger CreateLogger(string categoryName)
    {
        LastCategory = categoryName;
        return logger;
    }

    public void AddProvider(ILoggerProvider provider) { }
    public void Dispose() { }
}
