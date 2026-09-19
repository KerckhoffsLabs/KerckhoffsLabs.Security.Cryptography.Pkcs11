using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>Test <see cref="ILogger"/> that records each emitted entry (level, id, rendered text).</summary>
/// <remarks>
/// Backed by a <see cref="ConcurrentQueue{T}"/>, not a plain <c>List&lt;T&gt;</c>: a
/// <see cref="CapturingLogger"/> installed via <c>Pkcs11Logging.SetLoggerFactory</c> is process-wide
/// state, so it can receive concurrent <see cref="Log"/> calls from unrelated tests running in
/// parallel elsewhere in the suite for as long as it stays installed. A plain list would throw
/// "Collection was modified" the moment a test enumerates <see cref="Entries"/> while another
/// thread's call is still adding to it.
/// </remarks>
internal sealed class CapturingLogger : ILogger
{
    public sealed record Entry(LogLevel Level, EventId EventId, string Message);

    private readonly ConcurrentQueue<Entry> _entries = new();

    /// <summary>A point-in-time snapshot; safe to enumerate even while other threads keep logging.</summary>
    public IReadOnlyList<Entry> Entries => [.. _entries];

    /// <summary>Controls <see cref="IsEnabled"/> so tests can exercise the level-disabled path.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Discards every entry captured so far.</summary>
    public void Clear()
    {
        while (_entries.TryDequeue(out _)) { }
    }

    IDisposable? ILogger.BeginScope<TState>(TState state) => null;

    public bool IsEnabled(LogLevel logLevel) => Enabled;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
        => _entries.Enqueue(new Entry(logLevel, eventId, formatter(state, exception)));
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
