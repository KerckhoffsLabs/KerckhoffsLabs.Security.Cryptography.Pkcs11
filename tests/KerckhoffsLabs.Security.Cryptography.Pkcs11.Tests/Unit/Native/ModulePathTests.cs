using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// A module's initializers run as soon as it is loaded, so where a path makes the loader look matters.
/// A fully qualified path and a relative path with a directory load as the OS loads them. A bare name is
/// never searched for in the current directory (nor in <c>PATH</c> on Windows), where a planted library
/// can win.
/// </summary>
/// <remarks>
/// The loading tests use copies of pkcs11-mock under unique names, so each is a module instance of its
/// own, apart from the one <c>MockBackendFixture</c> keeps loaded. One test changes the process's current
/// directory, so the class runs in a collection of its own, outside the parallel ones.
/// </remarks>
[Collection(ModulePathCollection.Name)]
public sealed class ModulePathTests
{
    [Theory]
    [InlineData("libsofthsm2.so")]
    [InlineData("softhsm2.dll")]
    public void Classify_FileNameWithoutADirectory_IsABareName(string path)
        => Assert.Equal(ModulePathKind.BareName, ModulePath.Classify(path));

    [Theory]
    [InlineData("./libsofthsm2.so")]
    [InlineData("lib/libsofthsm2.so")]
    [InlineData("../libsofthsm2.so")]
    public void Classify_PathWithADirectory_IsRelative(string path)
        => Assert.Equal(ModulePathKind.Relative, ModulePath.Classify(path));

    [Fact]
    public void Classify_FullyQualifiedPath()
        => Assert.Equal(ModulePathKind.FullyQualified, ModulePath.Classify(Path.Join(Path.GetTempPath(), "libx.so")));

    // Windows-only forms: a drive-relative path resolves against that drive's current directory, and a
    // rooted one against the current drive. Elsewhere '\' is an ordinary file-name character.
    [Theory]
    [InlineData(@"C:softhsm2.dll")]
    [InlineData(@"\softhsm2.dll")]
    [InlineData(@"..\softhsm2.dll")]
    public void Classify_WindowsPartiallyRootedPaths_AreRelative(string path)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows path syntax.");
        Assert.Equal(ModulePathKind.Relative, ModulePath.Classify(path));
    }

    [Fact]
    public void FullyQualifiedPath_ReachesTheLoader()
    {
        string path = Path.Join(Path.GetTempPath(), $"no-such-module-{Guid.NewGuid():N}.so");

        Assert.Throws<DllNotFoundException>(() => Pkcs11Library.Load(path));
    }

    // Not refused up front: a bare name goes to the library search, which does not find this one.
    [Fact]
    public void BareName_ReachesTheLibrarySearch()
        => Assert.Throws<DllNotFoundException>(() => Pkcs11Library.Load($"no-such-module-{Guid.NewGuid():N}.so"));

    [Fact]
    public void BareName_IsFoundInThisLibrarysDirectory()
    {
        string name = UniqueModuleName();
        string copy = CopyMockTo(AppContext.BaseDirectory, name);
        try
        {
            using Pkcs11Library library = Pkcs11Library.Load(name);
            Assert.NotEmpty(library.GetInfo().ManufacturerId);
        }
        finally
        {
            TryDelete(copy);
        }
    }

    // The planted-library case: a module that exists only in the current directory is not what a bare name
    // loads. Linux's dlopen never searches there; on Windows the restricted search and on macOS the
    // library's own resolution keep it out.
    [Fact]
    public void BareName_IsNotFoundInTheCurrentDirectory()
    {
        string dir = Directory.CreateTempSubdirectory("pkcs11-cwd-").FullName;
        string name = UniqueModuleName();
        string copy = CopyMockTo(dir, name);
        string previous = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = dir;
            Assert.Throws<DllNotFoundException>(() => Pkcs11Library.Load(name));
        }
        finally
        {
            Environment.CurrentDirectory = previous;
            TryDelete(copy);
            TryDelete(dir);
        }
    }

    [Fact]
    public void RelativePathWithADirectory_Loads_AndLogsAWarning()
    {
        string dir = Directory.CreateTempSubdirectory("pkcs11-rel-").FullName;
        string name = UniqueModuleName();
        string copy = CopyMockTo(Path.Join(dir, "modules"), name);
        string previous = Environment.CurrentDirectory;
        var logger = new CapturingLogger();
        try
        {
            Environment.CurrentDirectory = dir;
            string relative = Path.Join("modules", name);

            using (Pkcs11Library library = Pkcs11Library.Load(relative, new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(logger) }))
                Assert.NotEmpty(library.GetInfo().ManufacturerId);

            CapturingLogger.Entry warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
            Assert.Contains(relative, warning.Message);
            Assert.Contains("relative path", warning.Message);
        }
        finally
        {
            Environment.CurrentDirectory = previous;
            TryDelete(copy);
            TryDelete(dir);
        }
    }

    [Fact]
    public void FullyQualifiedPath_LogsNoWarning()
    {
        string dir = Directory.CreateTempSubdirectory("pkcs11-abs-").FullName;
        var logger = new CapturingLogger();
        try
        {
            using (Pkcs11Library.Load(CopyMockTo(dir, UniqueModuleName()), new Pkcs11LibraryOptions { LoggerFactory = new CapturingLoggerFactory(logger) }))
            {
            }

            Assert.DoesNotContain(logger.Entries, e => e.Level == LogLevel.Warning);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    // --- the macOS bare-name search: dyld's order without the current directory --------------------------
    // Pure: takes the directories and environment as inputs, so these run on every OS.

    [Fact]
    public void MacOSSearch_FollowsDyldOrder()
    {
        // dyld's search paths are ':'-separated, which a Windows drive path (C:\...) cannot be written in.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "':'-separated search paths cannot hold a Windows drive path.");
        using var dirs = new TempDirs(5);
        string name = UniqueModuleName();
        string[] env = [dirs[1], dirs[2], dirs[3], dirs[4]];   // DYLD_LIBRARY_PATH, LD_LIBRARY_PATH, fallback
        Func<string, string?> getEnv = Env(("DYLD_LIBRARY_PATH", env[0]), ("LD_LIBRARY_PATH", env[1]),
            ("DYLD_FALLBACK_LIBRARY_PATH", $"{env[2]}:{env[3]}"));

        // Each step only when every earlier one lacks the module.
        for (int i = 4; i >= 0; i--)
        {
            File.WriteAllBytes(Path.Join(dirs[i], name), []);
            Assert.Equal(Path.Join(dirs[i], name), ModulePath.ResolveBareNameOnMacOS(name, dirs[0], getEnv));
        }
    }

    [Fact]
    public void MacOSSearch_NeverLooksInTheCurrentDirectory()
    {
        using var dirs = new TempDirs(2);
        string name = UniqueModuleName();
        File.WriteAllBytes(Path.Join(dirs[1], name), []);
        string previous = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = dirs[1];

            // Not searched as such, and not reachable through a relative or empty search-path entry either.
            Assert.Null(ModulePath.ResolveBareNameOnMacOS(name, dirs[0],
                Env(("DYLD_LIBRARY_PATH", ".:"), ("LD_LIBRARY_PATH", "./"), ("DYLD_FALLBACK_LIBRARY_PATH", "::."))));
        }
        finally
        {
            Environment.CurrentDirectory = previous;
        }
    }

    [Fact]
    public void MacOSSearch_UsesDyldsDefaultFallback_WhenNoneIsSet()
    {
        using var dirs = new TempDirs(1);
        var asked = new List<string>();

        Assert.Null(ModulePath.ResolveBareNameOnMacOS(UniqueModuleName(), dirs[0], variable =>
        {
            asked.Add(variable);
            return null;
        }));
        Assert.Equal(["DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"], asked);
        Assert.Equal("/usr/local/lib:/usr/lib", ModulePath.MacOSDefaultFallbackPath);
    }

    // The macOS branch of Load, driven on whatever OS runs the tests: the name is resolved first, then loaded
    // by the full path found, so the platform loader never sees a bare name.
    [Fact]
    public void ResolvingLoad_LoadsTheModuleFoundInTheApplicationDirectory()
    {
        string name = UniqueModuleName();
        string copy = CopyMockTo(AppContext.BaseDirectory, name);
        try
        {
            IntPtr handle = ModulePath.Load(name, resolveBareNameItself: true);
            Assert.NotEqual(IntPtr.Zero, handle);
            NativeLibrary.Free(handle);
        }
        finally
        {
            TryDelete(copy);
        }
    }

    [Fact]
    public void ResolvingLoad_ModuleOnlyInTheCurrentDirectory_IsNotFound()
    {
        string dir = Directory.CreateTempSubdirectory("pkcs11-cwd-").FullName;
        string name = UniqueModuleName();
        CopyMockTo(dir, name);
        string previous = Environment.CurrentDirectory;
        try
        {
            Environment.CurrentDirectory = dir;

            var e = Assert.Throws<DllNotFoundException>(() => ModulePath.Load(name, resolveBareNameItself: true));
            Assert.Contains(name, e.Message);
            Assert.Contains("never searched for in the current directory", e.Message);
        }
        finally
        {
            Environment.CurrentDirectory = previous;
            TryDelete(dir);
        }
    }

    private static Func<string, string?> Env(params (string Name, string Value)[] variables)
        => name => variables.FirstOrDefault(v => v.Name == name).Value;

    /// <summary>Fresh temp directories, deleted on dispose.</summary>
    private sealed class TempDirs : IDisposable
    {
        private readonly string[] _paths;

        public TempDirs(int count)
            => _paths = [.. Enumerable.Range(0, count).Select(_ => Directory.CreateTempSubdirectory("pkcs11-dir-").FullName)];

        public string this[int index] => _paths[index];

        public void Dispose()
        {
            foreach (string path in _paths)
                TryDelete(path);
        }
    }

    private static string UniqueModuleName()
        => $"pkcs11-mock-{Guid.NewGuid():N}{Path.GetExtension(Settings.MockLibraryPath)}";

    private static string CopyMockTo(string directory, string name)
    {
        Assert.True(File.Exists(Settings.MockLibraryPath), $"pkcs11-mock not found at '{Settings.MockLibraryPath}'.");
        Directory.CreateDirectory(directory);
        string copy = Path.Join(directory, name);
        File.Copy(Settings.MockLibraryPath, copy);
        return copy;
    }

    // Best-effort: Windows can keep a just-freed module's file locked for a moment. A copy left behind in a
    // temp directory must not fail the test, but it is reported rather than hidden.
    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
            else
                File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            TestContext.Current.SendDiagnosticMessage($"Could not delete '{path}': {ex.Message}");
        }
    }
}

/// <summary>Runs <see cref="ModulePathTests"/> alone: one of them changes the process's current directory.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ModulePathCollection
{
    public const string Name = "ModulePath";
}
