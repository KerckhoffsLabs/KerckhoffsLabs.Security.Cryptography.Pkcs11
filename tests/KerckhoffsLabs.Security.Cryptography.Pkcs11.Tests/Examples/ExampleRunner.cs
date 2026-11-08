using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;
using Xunit.Sdk;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Examples;

/// <summary>
/// Runs one documentation example on one backend. A backend that lacks what the example needs skips
/// it, except on the full-backend CI leg (<c>PKCS11_TEST_REQUIRE_EXAMPLE_COVERAGE=1</c>) for a backend in
/// the example's <see cref="ExampleCase.MustRunOn"/>: there the skip is a failure, so no example can stop
/// running everywhere without CI noticing.
/// </summary>
internal static class ExampleRunner
{
    public static bool CoverageRequired { get; } =
        string.Equals(Environment.GetEnvironmentVariable("PKCS11_TEST_REQUIRE_EXAMPLE_COVERAGE"), "1", StringComparison.Ordinal);

    public static void Run(IPkcs11Backend backend, ExampleBackend which, string name) =>
        Run(backend, which, ExampleCatalog.Get(name), CoverageRequired);

    internal static void Run(IPkcs11Backend backend, ExampleBackend which, ExampleCase example, bool coverageRequired)
    {
        CKM[] missing = [.. example.Requires.Where(m => !backend.Supports(m))];
        string? reason =
            missing.Length > 0 ? $"{which} does not advertise {string.Join(", ", missing)}"
            : example.NeedsUserLogin && !backend.RequiresUserLogin ? $"{which}'s token takes no user login"
            : example.Unsupported?.Invoke(backend)
                ?? (example.LoadsModule ? ExampleGates.SecondModuleInstance(backend) : null);

        bool required = coverageRequired && example.MustRunOn.HasFlag(which);
        if (reason is not null)
        {
            if (required)
                throw new XunitException($"Example {example.Name} must run on {which}, but {reason}.");
            Assert.Skip($"{reason}.");
        }

        try
        {
            RunRetryingLogin(backend, example);
        }
        catch (SkipException skip) when (required)
        {
            // A skip from inside the example (a platform that lacks the BCL side, say) is still a skip on
            // a backend the example must run on: on the full CI leg it fails like any other.
            throw new XunitException($"Example {example.Name} must run on {which}, but it skipped: {skip.Message}");
        }
    }

    // opencryptoki's soft token now and then fails a C_Login with CKR_GENERAL_ERROR under CI load, which
    // OpenCryptokiBackendFixture.OpenSession retries for the fixture's own sessions. An example that loads
    // the module logs in itself, so it gets the same retry here. Running it again is safe: each run uses a
    // fresh label and destroys what it made. Any other failure, or a third failed login, propagates. The
    // cleanup's session comes from the fixture, which retries its own login; when the cleanup fails after the
    // example did, the example's exception is the one kept (ExampleCatalog.RunThenCleanUp).
    private static void RunRetryingLogin(IPkcs11Backend backend, ExampleCase example)
    {
        const int maxAttempts = 3;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                example.Run(backend);
                return;
            }
            catch (Pkcs11Exception ex) when (backend is OpenCryptokiBackendFixture
                && ex.ReturnValue == CKR.CKR_GENERAL_ERROR
                && ex.Method.StartsWith("C_Login", StringComparison.Ordinal)
                && attempt < maxAttempts)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(200 * attempt));
            }
        }
    }
}
