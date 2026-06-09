using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Per-test-run configuration. All values are environment-driven so
/// developers can point the suite at any PKCS#11 module.
/// </summary>
public static class Settings
{
    /// <summary>
    /// Path to the pkcs11-mock shared library. Falls back to a path next
    /// to the test assembly when the env var is unset.
    /// </summary>
    public static string MockLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_MOCK_LIBRARY")
        ?? DefaultMockPath();

    /// <summary>
    /// Optional path to a SoftHSM2 PKCS#11 library. Tests that require it
    /// skip themselves when this resolves to null.
    /// </summary>
    public static string? SoftHsmLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_SOFTHSM_LIBRARY");

    /// <summary>
    /// Normal-user PIN for fixture tokens. Matches the pkcs11-mock default.
    /// Set PKCS11_TEST_USER_PIN to override (e.g. for SoftHSM2).
    /// </summary>
    public static string UserPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_USER_PIN") ?? "11111111";

    /// <summary>
    /// SO PIN for fixture tokens. Matches the pkcs11-mock default.
    /// </summary>
    public static string SoPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_SO_PIN") ?? "11111111";

    /// <summary>
    /// Optional path to a system-installed opencryptoki PKCS#11 library — a second, independent real
    /// backend for cross-implementation coverage. Tests skip when this resolves to null; the token is
    /// provisioned out-of-band (by CI), not by the fixture.
    /// </summary>
    public static string? OpenCryptokiLibraryPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_LIBRARY");

    /// <summary>Token label of the provisioned opencryptoki token (must match what CI initialized).</summary>
    public static string OpenCryptokiTokenLabel =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_TOKEN") ?? "kl-octk";

    /// <summary>Normal-user PIN for the opencryptoki token.</summary>
    public static string OpenCryptokiUserPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_USER_PIN") ?? "12345678";

    /// <summary>SO PIN for the opencryptoki token (opencryptoki's default is 87654321).</summary>
    public static string OpenCryptokiSoPin =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_OPENCRYPTOKI_SO_PIN") ?? "87654321";

    private static string DefaultMockPath()
    {
        string baseDir = AppContext.BaseDirectory;
        string rid =
            // Windows keys off the PROCESS architecture (the testhost), so a 32-bit run finds the
            // x86 mock — an x64 mock can't load into an x86 process (BadImageFormat).
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? RuntimeInformation.ProcessArchitecture switch
                {
                    Architecture.X86 => "win-x86",
                    Architecture.Arm64 => "win-arm64",
                    _ => "win-x64",
                }
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? (RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "osx-arm64" : "osx-x64")
            : RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "linux-arm64"
            : "linux-x64";

        string fileName =
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "pkcs11-mock.dll" :
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "pkcs11-mock.dylib"
            : "pkcs11-mock.so";

        return Path.Combine(baseDir, "runtimes", rid, "native", fileName);
    }
}
