using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
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
            : example.Unsupported?.Invoke(backend);

        bool required = coverageRequired && example.MustRunOn.HasFlag(which);
        if (reason is not null)
        {
            if (required)
                throw new XunitException($"Example {example.Name} must run on {which}, but {reason}.");
            Assert.Skip($"{reason}.");
        }

        try
        {
            example.Run(backend);
        }
        catch (SkipException skip) when (required)
        {
            // A skip from inside the example (a platform that lacks the BCL side, say) is still a skip on
            // a backend the example must run on: on the full CI leg it fails like any other.
            throw new XunitException($"Example {example.Name} must run on {which}, but it skipped: {skip.Message}");
        }
    }
}
