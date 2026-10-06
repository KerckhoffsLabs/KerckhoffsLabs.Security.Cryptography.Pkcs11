using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// The session <c>C_OpenSession</c> returns is owned before any consumer code (a logger, a logger
/// factory) runs. If that code throws, the session is closed rather than left open with nothing to
/// close it, which on a token with a small session limit is a denial of service.
/// </summary>
public sealed class OpenSessionOwnershipTests
{
    private const ulong SlotId = 3;

    [Fact]
    public void LoggerThrowsOnTheOpenedLine_TheSessionIsClosed()
    {
        var fake = new SessionFake();
        var slot = new Pkcs11Slot(fake, SlotId, new ThrowingLoggerFactory(throwOnLog: "Opened"));

        Assert.Throws<LoggerFault>(() => slot.OpenSession());

        Assert.Equal([(NativeCULong)7UL], fake.Closed);
    }

    [Fact]
    public void LoggerFactoryThrowsForTheSession_TheSessionIsClosed()
    {
        var fake = new SessionFake();
        var slot = new Pkcs11Slot(fake, SlotId, new ThrowingLoggerFactory(throwOnCategory: typeof(Pkcs11Session).FullName));

        Assert.Throws<LoggerFault>(() => slot.OpenSession());

        Assert.Equal([(NativeCULong)7UL], fake.Closed);
    }

    [Fact]
    public void ModuleReturnsTheInvalidHandle_IsRefused_AndNothingIsClosed()
    {
        var fake = new SessionFake { SessionId = (NativeCULong)CK.CK_INVALID_HANDLE };

        Assert.Throws<ArgumentException>(() => new Pkcs11Slot(fake, SlotId).OpenSession());

        Assert.Empty(fake.Closed);
    }

    [Fact]
    public void NothingThrows_TheSessionStaysOpenUntilDisposed()
    {
        var fake = new SessionFake();

        using (Pkcs11Session session = new Pkcs11Slot(fake, SlotId).OpenSession())
            Assert.Empty(fake.Closed);

        Assert.Equal([(NativeCULong)7UL], fake.Closed);
    }

    private sealed class SessionFake : FakeLowLevelPkcs11Library
    {
        public NativeCULong SessionId { get; init; } = (NativeCULong)7UL;
        public List<NativeCULong> Closed { get; } = [];

        public override CKR C_OpenSession(NativeCULong slotId, NativeCULong flags, IntPtr application, IntPtr notify, ref NativeCULong session)
        {
            session = SessionId;
            return CKR.CKR_OK;
        }

        public override CKR C_CloseSession(NativeCULong session)
        {
            Closed.Add(session);
            return CKR.CKR_OK;
        }
    }

    private sealed class LoggerFault : Exception;

    /// <summary>Throws from <c>CreateLogger</c> for one category, or from <c>Log</c> for a message prefix.</summary>
    private sealed class ThrowingLoggerFactory(string? throwOnCategory = null, string? throwOnLog = null) : ILoggerFactory, ILogger
    {
        public ILogger CreateLogger(string categoryName)
            => categoryName == throwOnCategory ? throw new LoggerFault() : this;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (throwOnLog is not null && formatter(state, exception).StartsWith(throwOnLog, StringComparison.Ordinal))
                throw new LoggerFault();
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void AddProvider(ILoggerProvider provider) { }
        public void Dispose() { }
    }
}
