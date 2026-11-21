using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

// Every call into the consumer's logger must run inside a CallOutScope (so a sink that calls back
// into a session is judged as the caller), forward its arguments and result unchanged, and leave the
// scope again on return, including when the sink throws.
public sealed class CallOutFencedLoggerTests
{
    private sealed class ProbeLogger : ILogger
    {
        public readonly List<string> Calls = [];
        public readonly List<bool> ActiveDuringCall = [];
        public object? LastState;
        public LogLevel? LastLevel;
        public EventId LastEventId;
        public Exception? LastException;
        public string? LastRendered;
        public IDisposable? ScopeToReturn;
        public bool EnabledToReturn;
        public bool Throw;

        private void Record(string call)
        {
            Calls.Add(call);
            ActiveDuringCall.Add(Pkcs11SessionCore.CallOutScope.Active);
            if (Throw)
                throw new InvalidOperationException(call);
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            Record(nameof(BeginScope));
            LastState = state;
            return ScopeToReturn;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            Record(nameof(IsEnabled));
            LastLevel = logLevel;
            return EnabledToReturn;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Record(nameof(Log));
            LastLevel = logLevel;
            LastEventId = eventId;
            LastState = state;
            LastException = exception;
            LastRendered = formatter(state, exception);
        }
    }

    private sealed class Scope : IDisposable
    {
        public void Dispose() { }
    }

    [Fact]
    public void BeginScope_ForwardsStateAndResult_InsideACallOut()
    {
        var scope = new Scope();
        var inner = new ProbeLogger { ScopeToReturn = scope };
        var logger = new CallOutFencedLogger(inner);

        var returned = logger.BeginScope("state");

        Assert.Same(scope, returned);
        Assert.Equal("state", inner.LastState);
        Assert.Equal([nameof(ILogger.BeginScope)], inner.Calls);
        Assert.Equal([true], inner.ActiveDuringCall);
        Assert.False(Pkcs11SessionCore.CallOutScope.Active);
    }

    [Fact]
    public void BeginScope_ForwardsANullScope()
    {
        var logger = new CallOutFencedLogger(new ProbeLogger());

        Assert.Null(logger.BeginScope(42));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IsEnabled_ForwardsLevelAndResult_InsideACallOut(bool enabled)
    {
        var inner = new ProbeLogger { EnabledToReturn = enabled };
        var logger = new CallOutFencedLogger(inner);

        Assert.Equal(enabled, logger.IsEnabled(LogLevel.Warning));
        Assert.Equal(LogLevel.Warning, inner.LastLevel);
        Assert.Equal([true], inner.ActiveDuringCall);
        Assert.False(Pkcs11SessionCore.CallOutScope.Active);
    }

    [Fact]
    public void Log_ForwardsEveryArgument_InsideACallOut()
    {
        var inner = new ProbeLogger();
        var logger = new CallOutFencedLogger(inner);
        var error = new InvalidOperationException("boom");

        logger.Log(LogLevel.Error, new EventId(7, "Seven"), "payload", error, (s, e) => $"{s}:{e!.Message}");

        Assert.Equal(LogLevel.Error, inner.LastLevel);
        Assert.Equal(new EventId(7, "Seven"), inner.LastEventId);
        Assert.Equal("payload", inner.LastState);
        Assert.Same(error, inner.LastException);
        Assert.Equal("payload:boom", inner.LastRendered);
        Assert.Equal([true], inner.ActiveDuringCall);
        Assert.False(Pkcs11SessionCore.CallOutScope.Active);
    }

    [Fact]
    public void ThrowingSink_LeavesTheCallOutOnEveryMember()
    {
        var inner = new ProbeLogger { Throw = true };
        var logger = new CallOutFencedLogger(inner);

        Assert.Throws<InvalidOperationException>(() => logger.BeginScope("s"));
        Assert.False(Pkcs11SessionCore.CallOutScope.Active);
        Assert.Throws<InvalidOperationException>(() => logger.IsEnabled(LogLevel.Information));
        Assert.False(Pkcs11SessionCore.CallOutScope.Active);
        Assert.Throws<InvalidOperationException>(() => logger.Log(LogLevel.Information, default, "s", null, (s, _) => s));
        Assert.False(Pkcs11SessionCore.CallOutScope.Active);

        Assert.Equal([true, true, true], inner.ActiveDuringCall);
    }

    [Fact]
    public void NestedCallOut_StaysActiveAfterTheLoggerReturns()
    {
        var inner = new ProbeLogger();
        var logger = new CallOutFencedLogger(inner);

        using (Pkcs11SessionCore.CallOutScope.Enter())
        {
            logger.Log(LogLevel.Debug, default, "s", null, (s, _) => s);
            Assert.True(Pkcs11SessionCore.CallOutScope.Active);
        }

        Assert.False(Pkcs11SessionCore.CallOutScope.Active);
        Assert.Equal([true], inner.ActiveDuringCall);
    }
}
