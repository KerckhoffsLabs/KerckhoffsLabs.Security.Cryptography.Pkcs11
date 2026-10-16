using System.Runtime.InteropServices;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>How the OS loader resolves a module path.</summary>
internal enum ModulePathKind
{
    /// <summary>A fully qualified path: loaded exactly as given.</summary>
    FullyQualified,

    /// <summary>A file name with no directory (<c>libsofthsm2.so</c>, <c>cryptoki.dll</c>): found by a library search.</summary>
    BareName,

    /// <summary>
    /// A path with a directory part that is not fully qualified (<c>modules/x.so</c>, <c>./x.so</c>, and on
    /// Windows <c>C:x.dll</c> or <c>\x.dll</c>): resolved against the current directory.
    /// </summary>
    Relative,
}

/// <summary>
/// Loads a PKCS#11 module the way the OS loader does, minus the search locations where a planted file can
/// win: the current directory, which Windows and macOS search for a bare name, and <c>PATH</c> on Windows.
/// </summary>
/// <remarks>
/// <para>
/// A fully qualified path is loaded as given. A relative path with a directory part is resolved against
/// the current directory here, with <see cref="Path.GetFullPath(string)"/>, and loaded by the full path:
/// Linux and macOS would do the same, but Windows' <c>LoadLibraryEx</c> appends a relative path to every
/// directory of its search (the application directory, <c>System32</c>, the current directory, then
/// <c>PATH</c>), so <c>modules\x.dll</c> could load from somewhere else entirely.
/// </para>
/// <para>
/// A bare name is searched for in this assembly's directory and the system's library directories, never
/// in the current directory:
/// </para>
/// <list type="bullet">
///   <item><description>
///     Windows: <see cref="DllImportSearchPath.SafeDirectories"/> (the application directory, <c>System32</c>
///     and directories added with <c>AddDllDirectory</c>), so neither the current directory nor <c>PATH</c>.
///   </description></item>
///   <item><description>
///     Linux: <c>dlopen</c>'s own search, which never includes the current directory, unless
///     <c>LD_LIBRARY_PATH</c> has an empty entry (<c>/opt/lib:</c>, a leading, trailing or doubled
///     <c>:</c>), which glibc reads as the current directory. That is the process environment's to get right.
///   </description></item>
///   <item><description>
///     macOS: dyld's <c>dlopen</c> does search the current directory for a bare name, so the name is never
///     handed to it. <see cref="ResolveBareNameOnMacOS"/> searches where .NET and dyld would, without the
///     current directory, and the module is loaded by the full path it finds.
///   </description></item>
/// </list>
/// </remarks>
internal static class ModulePath
{
    /// <summary>Where a bare module name is searched for.</summary>
    internal const DllImportSearchPath BareNameSearch = DllImportSearchPath.SafeDirectories | DllImportSearchPath.AssemblyDirectory;

    internal static ModulePathKind Classify(string path)
    {
        if (Path.IsPathFullyQualified(path))
            return ModulePathKind.FullyQualified;

        // Any directory separator, or a Windows drive or root (C:x.dll, \x.dll), makes the OS resolve the
        // path against the current directory rather than search for it.
        bool hasDirectory = path.Contains(Path.DirectorySeparatorChar)
            || path.Contains(Path.AltDirectorySeparatorChar)
            || Path.IsPathRooted(path);
        return hasDirectory ? ModulePathKind.Relative : ModulePathKind.BareName;
    }

    /// <summary>dyld's fallback directories when <c>DYLD_FALLBACK_LIBRARY_PATH</c> is unset.</summary>
    internal const string MacOSDefaultFallbackPath = "/usr/local/lib:/usr/lib";

    internal static IntPtr Load(string path) => Load(path, resolveBareNameItself: OperatingSystem.IsMacOS());

    /// <param name="path">The module path.</param>
    /// <param name="resolveBareNameItself">
    /// Resolve a bare name with <see cref="ResolveBareNameOnMacOS"/> and load the full path it finds, rather than
    /// hand the name to the platform loader. Set on macOS; a parameter so the branch can be tested on any OS.
    /// </param>
    internal static IntPtr Load(string path, bool resolveBareNameItself)
    {
        switch (Classify(path))
        {
            case ModulePathKind.FullyQualified:
                return NativeLibrary.Load(path);
            case ModulePathKind.Relative:
                // Against the current directory only; see the remarks for why the loader isn't trusted to.
                return NativeLibrary.Load(Path.GetFullPath(path));
        }

        if (!resolveBareNameItself)
            return NativeLibrary.Load(path, typeof(ModulePath).Assembly, BareNameSearch);

        string? resolved = ResolveBareNameOnMacOS(
            path, NativeAssetDirectories(), AppContext.BaseDirectory, Environment.GetEnvironmentVariable);
        return resolved is not null
            ? NativeLibrary.Load(resolved)
            : throw new DllNotFoundException(
                $"PKCS#11 module '{path}' was not found in the application's native-asset directories, the application " +
                "directory, DYLD_LIBRARY_PATH or dyld's fallback directories. A bare name is never searched for in the " +
                "current directory; pass a fully qualified path to load a module from there.");
    }

    /// <summary>
    /// Where bare <paramref name="name"/> would be found on macOS, without the current directory:
    /// <list type="number">
    ///   <item><description>
    ///     .NET's own probing: the application's native-asset directories (<c>NATIVE_DLL_SEARCH_DIRECTORIES</c>,
    ///     where a NuGet package's <c>runtimes/osx*/native</c> files land), then the application directory.
    ///   </description></item>
    ///   <item><description>
    ///     dyld's search for a leaf name, minus the current directory and the caller's <c>LC_RPATH</c>
    ///     entries: <c>DYLD_LIBRARY_PATH</c>, then <c>DYLD_FALLBACK_LIBRARY_PATH</c>, or
    ///     <see cref="MacOSDefaultFallbackPath"/> when it is unset.
    ///   </description></item>
    /// </list>
    /// Each of <see cref="NameVariants"/> is looked for in every directory before the next variant is tried.
    /// <see langword="null"/> when none is found.
    /// </summary>
    /// <remarks>Takes its inputs as parameters so the search order can be tested on any OS.</remarks>
    internal static string? ResolveBareNameOnMacOS(
        string name, IEnumerable<string> nativeAssetDirectories, string applicationDirectory, Func<string, string?> getEnvironmentVariable)
    {
        // Only fully qualified entries: a relative or empty one would resolve against the current directory again.
        string[] directories = [.. nativeAssetDirectories
            .Append(applicationDirectory)
            .Concat(Split(getEnvironmentVariable("DYLD_LIBRARY_PATH")))
            .Concat(Split(getEnvironmentVariable("DYLD_FALLBACK_LIBRARY_PATH") ?? MacOSDefaultFallbackPath))
            .Where(Path.IsPathFullyQualified)];

        return NameVariants(name)
            .SelectMany(variant => directories.Select(directory => Path.Join(directory, variant)))
            .FirstOrDefault(File.Exists);

        static IEnumerable<string> Split(string? searchPath)
            => (searchPath ?? "").Split(':', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// The file names a bare <paramref name="name"/> stands for, as .NET's probing tries them on other
    /// platforms: the name itself, then with the <c>.dylib</c> suffix and the <c>lib</c> prefix it lacks.
    /// </summary>
    internal static IEnumerable<string> NameVariants(string name)
    {
        yield return name;
        bool hasSuffix = name.EndsWith(".dylib", StringComparison.Ordinal);
        bool hasPrefix = name.StartsWith("lib", StringComparison.Ordinal);
        if (!hasSuffix)
            yield return name + ".dylib";
        if (!hasPrefix)
        {
            if (!hasSuffix)
                yield return "lib" + name + ".dylib";
            yield return "lib" + name;
        }
    }

    // The application's native-asset directories from its deps.json, as the host passes them to the runtime.
    private static IEnumerable<string> NativeAssetDirectories()
        => (AppContext.GetData("NATIVE_DLL_SEARCH_DIRECTORIES") as string ?? "")
            .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
}
