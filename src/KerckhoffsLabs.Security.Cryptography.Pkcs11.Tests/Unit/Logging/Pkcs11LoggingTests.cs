using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Logging;

// Pkcs11Logging holds a process-wide ILoggerFactory. These tests mutate it, so they live in one
// class (xUnit runs a class's tests sequentially) and always reset to the NullLoggerFactory default
// in a finally — SetLoggerFactory(null) restores it.
//
// CreateLogger(Type) returns the factory's logger directly, so reference-equality assertions use it;
// the generic CreateLogger<T> wraps the result in a Logger<T>, so that one is checked behaviorally.
public sealed class Pkcs11LoggingTests
{
    [Fact]
    public void Default_IsNullLogger()
    {
        Pkcs11Logging.SetLoggerFactory(null);
        try
        {
            Assert.Same(NullLogger.Instance, Pkcs11Logging.CreateLogger(typeof(Pkcs11LoggingTests)));
        }
        finally { Pkcs11Logging.SetLoggerFactory(null); }
    }

    [Fact]
    public void SetLoggerFactory_Installed_CreateLoggerByTypeUsesIt()
    {
        var captured = new CapturingLogger();
        Pkcs11Logging.SetLoggerFactory(new CapturingLoggerFactory(captured));
        try
        {
            Assert.Same(captured, Pkcs11Logging.CreateLogger(typeof(Pkcs11LoggingTests)));
        }
        finally { Pkcs11Logging.SetLoggerFactory(null); }
    }

    [Fact]
    public void SetLoggerFactory_Null_ResetsToNullLogger()
    {
        Pkcs11Logging.SetLoggerFactory(new CapturingLoggerFactory(new CapturingLogger()));
        try
        {
            Pkcs11Logging.SetLoggerFactory(null); // reset
            Assert.Same(NullLogger.Instance, Pkcs11Logging.CreateLogger(typeof(Pkcs11LoggingTests)));
        }
        finally { Pkcs11Logging.SetLoggerFactory(null); }
    }

    [Fact]
    public void CreateLogger_ByType_UsesFullNameCategory()
    {
        var factory = new CapturingLoggerFactory(new CapturingLogger());
        Pkcs11Logging.SetLoggerFactory(factory);
        try
        {
            Pkcs11Logging.CreateLogger(typeof(Pkcs11LoggingTests));
            Assert.Equal(typeof(Pkcs11LoggingTests).FullName, factory.LastCategory);
        }
        finally { Pkcs11Logging.SetLoggerFactory(null); }
    }

    [Fact]
    public void CreateLogger_ByType_NullFullName_FallsBackToName()
    {
        // A generic type parameter has a null Type.FullName, so the category must fall back to
        // Type.Name — the only branch of CreateLogger(Type) the other tests don't reach.
        Type genericParam = typeof(List<>).GetGenericArguments()[0];
        Assert.Null(genericParam.FullName); // precondition that selects the fallback

        var factory = new CapturingLoggerFactory(new CapturingLogger());
        Pkcs11Logging.SetLoggerFactory(factory);
        try
        {
            Pkcs11Logging.CreateLogger(genericParam);
            Assert.Equal(genericParam.Name, factory.LastCategory);
        }
        finally { Pkcs11Logging.SetLoggerFactory(null); }
    }

    [Fact]
    public void CreateLoggerGeneric_DispatchesToInstalledFactory()
    {
        var captured = new CapturingLogger();
        var factory = new CapturingLoggerFactory(captured);
        Pkcs11Logging.SetLoggerFactory(factory);
        try
        {
            var logger = Pkcs11Logging.CreateLogger<Pkcs11LoggingTests>();
            logger.LogInformation("hello");

            Assert.NotNull(factory.LastCategory); // the Logger<T> queried the factory
            Assert.Contains(captured.Entries, e => e.Message == "hello" && e.Level == LogLevel.Information);
        }
        finally { Pkcs11Logging.SetLoggerFactory(null); }
    }
}
