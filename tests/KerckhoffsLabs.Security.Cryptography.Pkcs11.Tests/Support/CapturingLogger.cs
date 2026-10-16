using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>Test <see cref="ILogger"/> that records each emitted entry (level, id, rendered text).</summary>
/// <remarks>
/// Backed by a <see cref="ConcurrentQueue{T}"/>, not a plain <c>List&lt;T&gt;</c>: a library, its
/// slots and its sessions can log from more than one thread (a finalizer, a parallel operation), and a
/// plain list would throw "Collection was modified" the moment a test enumerates
/// <see cref="Entries"/> while another thread's call is still adding to it.
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
/// Records all categories rather than the last one: a library hands its factory down to every slot and
/// session it produces, so one factory is asked for several categories. A test should check that its
/// category is present rather than that it was the last one asked for.
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
