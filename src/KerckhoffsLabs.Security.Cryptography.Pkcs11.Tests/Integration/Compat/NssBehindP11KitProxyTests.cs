using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Compat;

/// <summary>
/// NSS softoken loaded through p11-kit's proxy module, which reports itself in <c>C_GetInfo</c> and
/// passes NSS's slot information on. NSS before 3.114 dereferences the <c>ulPasswordLen</c> of
/// <c>CKM_PKCS5_PBKD2</c>, so unless the library recognizes it from its slot it sends the corrected
/// structure, and the test host dies with SIGSEGV. Point <c>PKCS11_TEST_NSS_LIBRARY</c> at such an NSS
/// (Ubuntu 24.04 ships 3.98) for this to be a regression test; with a later NSS it checks the
/// plumbing only.
/// </summary>
/// <remarks>
/// p11-kit reads its module configuration from <c>~/.config/pkcs11/modules</c> when the proxy is
/// initialized, so the test points the process's native <c>HOME</c> at a temporary directory for that
/// call. Its own collection, run with nothing else alongside, keeps any other test from reading
/// <c>HOME</c> meanwhile, and from having the same NSS initialized at the same time.
/// </remarks>
[Collection(Name)]
public sealed class NssBehindP11KitProxyTests
{
    public const string Name = "NssBehindP11KitProxy";

    private static readonly string[] ProxyCandidates =
    [
        "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",
        "/usr/lib/aarch64-linux-gnu/p11-kit-proxy.so",
        "/usr/lib64/p11-kit-proxy.so",
        "/usr/lib/p11-kit-proxy.so",
    ];

    private static string? ProxyPath =>
        Environment.GetEnvironmentVariable("PKCS11_TEST_P11KIT_PROXY") is { Length: > 0 } configured
            ? configured
            : ProxyCandidates.FirstOrDefault(File.Exists);

    private static string? NssPath => Settings.NssLibraryPath ?? NssBackendFixture.BuiltLibraryPath();

    public static bool ProxiedNssAvailable =>
        OperatingSystem.IsLinux() && ProxyPath is { } proxy && File.Exists(proxy)
        && NssPath is { } nss && File.Exists(nss);

    [Fact(SkipUnless = nameof(ProxiedNssAvailable), Skip = "Requires " + nameof(ProxiedNssAvailable))]
    public void Pbkdf2_ProxiedNss_DetectedFromTheSlot_AndMatchesTheBcl()
    {
        using var library = LoadProxyOverNss();

        // Otherwise the module-level check decides, and this proves nothing about the slot fallback.
        Assert.NotEqual("Mozilla Foundation", library.GetInfo().ManufacturerId);

        if (library.GetSlotList().FirstOrDefault(s => s.GetTokenInfo().Label.TrimEnd() == Settings.NssTokenLabel)
            is not { } slot)
        {
            Assert.Skip("p11-kit did not load NSS: user module configuration is disabled on this host.");
            return;
        }
        SlotInfo slotInfo = slot.GetSlotInfo();
        Assert.Equal("Mozilla Foundation", slotInfo.ManufacturerId);

        byte[] password = Encoding.UTF8.GetBytes("passwordPASSWORDpassword");
        byte[] salt = Encoding.UTF8.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
        byte[] actual;
        using (var session = library.OpenSessionWithoutLogin(Settings.NssTokenLabel))
        using (session.UsePolicy(CryptoPolicy.AllowInsecure))
            actual = Rfc2898DeriveBytesPkcs11.Pbkdf2(session, password, salt, 4096, HashAlgorithmName.SHA256, 32);

        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(password, salt, 4096, HashAlgorithmName.SHA256, 32), actual);
        Assert.Equal(
            slotInfo.HardwareVersion is { Major: 3, Minor: < 114 },
            library.LowLevelLibrary!.Pbkdf2PasswordLengthByReferenceBySlot[slot.SlotId.Value]);
    }

    // Loads the proxy with a user configuration that adds the NSS under test as a module, then puts
    // HOME back: p11-kit reads the configuration only while the proxy initializes.
    private static Pkcs11Library LoadProxyOverNss()
    {
        string home = Directory.CreateTempSubdirectory("kl-p11kit-").FullName;
        string? originalHome = Environment.GetEnvironmentVariable("HOME");
        try
        {
            string modules = Directory.CreateDirectory(Path.Join(home, ".config", "pkcs11", "modules")).FullName;
            // x-init-reserved is what p11-kit hands the module in C_Initialize's pReserved: the same
            // parameter string the NSS fixture passes, without which NSS before 3.52 refuses to start.
            File.WriteAllText(Path.Join(modules, "kl-nss-under-test.module"),
                $"module: {Path.GetFullPath(NssPath!)}\ncritical: yes\nx-init-reserved: {Settings.NssModuleParameters}\n");

            SoftHsmBackendFixture.SetNativeEnv("HOME", home);
            try
            {
                return Pkcs11Library.Load(ProxyPath!);
            }
            finally
            {
                SoftHsmBackendFixture.SetOrUnsetNativeEnv("HOME", originalHome);
            }
        }
        finally
        {
            Directory.Delete(home, recursive: true);
        }
    }
}

/// <summary>Runs <see cref="NssBehindP11KitProxyTests"/> with no other test alongside.</summary>
[CollectionDefinition(NssBehindP11KitProxyTests.Name, DisableParallelization = true)]
public sealed class NssBehindP11KitProxyCollection;
