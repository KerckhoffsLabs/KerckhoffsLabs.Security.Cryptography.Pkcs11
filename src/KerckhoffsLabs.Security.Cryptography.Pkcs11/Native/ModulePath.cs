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
/// A fully qualified path is loaded as given, and a relative path with a directory part is resolved
/// against the current directory, as every OS does. Neither involves a search.
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
///     Linux: <c>dlopen</c>'s own search, which never includes the current directory.
///   </description></item>
///   <item><description>
///     macOS: dyld's <c>dlopen</c> does search the current directory for a bare name, so the name is never
///     handed to it. <see cref="ResolveBareNameOnMacOS"/> follows dyld's order without that step and the
///     module is loaded by the full path it finds.
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
        if (Classify(path) != ModulePathKind.BareName)
            return NativeLibrary.Load(path);

        if (!resolveBareNameItself)
            return NativeLibrary.Load(path, typeof(ModulePath).Assembly, BareNameSearch);

        string? resolved = ResolveBareNameOnMacOS(path, AppContext.BaseDirectory, Environment.GetEnvironmentVariable);
        return resolved is not null
            ? NativeLibrary.Load(resolved)
            : throw new DllNotFoundException(
                $"PKCS#11 module '{path}' was not found in the application directory, DYLD_LIBRARY_PATH, LD_LIBRARY_PATH " +
                "or dyld's fallback directories. A bare name is never searched for in the current directory; pass a " +
                "fully qualified path to load a module from there.");
    }

    /// <summary>
    /// Where dyld would find bare <paramref name="name"/>, minus the current directory: the application
    /// directory, then <c>DYLD_LIBRARY_PATH</c>, <c>LD_LIBRARY_PATH</c>, and the fallback directories
    /// (<c>DYLD_FALLBACK_LIBRARY_PATH</c>, or <see cref="MacOSDefaultFallbackPath"/> when it is unset).
    /// <see langword="null"/> when none holds it.
    /// </summary>
    /// <remarks>Takes its inputs as parameters so the search order can be tested on any OS.</remarks>
    internal static string? ResolveBareNameOnMacOS(string name, string applicationDirectory, Func<string, string?> getEnvironmentVariable)
    {
        IEnumerable<string> directories =
            new[] { applicationDirectory }
                .Concat(Split(getEnvironmentVariable("DYLD_LIBRARY_PATH")))
                .Concat(Split(getEnvironmentVariable("LD_LIBRARY_PATH")))
                .Concat(Split(getEnvironmentVariable("DYLD_FALLBACK_LIBRARY_PATH") ?? MacOSDefaultFallbackPath));

        // Only fully qualified entries: a relative one would resolve against the current directory again.
        return directories
            .Where(Path.IsPathFullyQualified)
            .Select(directory => Path.Join(directory, name))
            .FirstOrDefault(File.Exists);

        static IEnumerable<string> Split(string? searchPath)
            => (searchPath ?? "").Split(':', StringSplitOptions.RemoveEmptyEntries);
    }
}
