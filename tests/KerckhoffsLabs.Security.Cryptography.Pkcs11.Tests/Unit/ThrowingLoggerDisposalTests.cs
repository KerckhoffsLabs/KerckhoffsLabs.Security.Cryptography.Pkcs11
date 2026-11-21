using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// A logger that throws on the disposal paths of the login model: <see cref="Pkcs11Login.Dispose"/> never throws, and
/// a session's disposal releases its hold of the login whatever its close threw, so the token is not left logged in.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class ThrowingLoggerDisposalTests : IDisposable
{
    private readonly ThrowingLogger _logger = new();
    private readonly LoginTokenModule _module;
    private readonly Pkcs11Library _library;
    private readonly SecurePin _pin;

    public ThrowingLoggerDisposalTests()
    {
        _module = new LoginTokenModule();
        _library = _module.Load(new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(_logger) });
        _pin = new SecurePin(_module.ExpectedPin);
    }

    public void Dispose()
    {
        _logger.Armed = false;
        _pin.Dispose();
        _library.Dispose();
        _module.Dispose();
    }

    private Pkcs11Slot Slot => Assert.Single(_library.GetSlotList());

    // The logger throws on the way to C_Logout: Dispose does not throw, and the login, left on the token, is logged out
    // by the next first login, which then checks the PIN.
    [Fact]
    public void LoginDispose_LoggerThrows_DoesNotThrow_NextLoginRecovers()
    {
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        _logger.Armed = true;

        login.Dispose();

        Assert.False(login.IsActive);
        _logger.Armed = false;
        using Pkcs11Login next = Slot.Login(TokenUser.User, _pin);
        Assert.True(next.IsActive);
        Assert.Equal(CKU.CKU_USER, _module.LoggedIn);
    }

    // A lent session whose disposal logs through a throwing logger still gives back its hold: the login ends, and the
    // next login is not refused as held (a leaked hold would keep it).
    [Fact]
    public void LentSessionDispose_LoggerThrows_HoldReleased()
    {
        _module.MaxSessions = 1;
        Pkcs11Login login = Slot.Login(TokenUser.User, _pin);
        Pkcs11Session session = login.OpenSession();
        Assert.True(session.IsLent);
        login.Dispose();

        _logger.Armed = true;
        Record.Exception(session.Dispose);
        _logger.Armed = false;

        Assert.False(login.IsActive);
        using Pkcs11Login next = Slot.Login(TokenUser.User, _pin);
        Assert.True(next.IsActive);
    }

    private sealed class ThrowingLogger : ILogger
    {
        public volatile bool Armed;

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (Armed)
                throw new InvalidOperationException("logger down");
        }
    }
}
