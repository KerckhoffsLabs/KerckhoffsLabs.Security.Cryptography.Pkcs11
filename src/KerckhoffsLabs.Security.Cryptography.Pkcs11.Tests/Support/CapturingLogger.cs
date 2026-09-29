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

/// <summary>Test <see cref="ILoggerFactory"/> that always returns <paramref name="logger"/> and records every category it is asked for.</summary>
/// <remarks>
/// Records all categories rather than the last one: once installed through
/// <c>Pkcs11Logging.SetLoggerFactory</c> the factory is process-wide, so library objects built by tests
/// running in parallel ask it for their own categories too. A single "last category" slot could be
/// overwritten between a test's call and its assertion; a test should check that its category is present.
/// </remarks>
internal sealed class CapturingLoggerFactory(ILogger logger) : ILoggerFactory
{
    private readonly ConcurrentQueue<string> _categories = new();

    public IReadOnlyCollection<string> Categories => [.. _categories];

    public ILogger CreateLogger(string categoryName)
    {
        _categories.Enqueue(categoryName);
        return logger;
    }

    public void AddProvider(ILoggerProvider provider) { }
    public void Dispose() { }
}
