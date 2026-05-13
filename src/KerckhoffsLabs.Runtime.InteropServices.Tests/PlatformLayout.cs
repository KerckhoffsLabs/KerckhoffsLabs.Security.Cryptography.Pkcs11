// Licensed under the MIT License

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

/// <summary>
/// Storage-width predicates for <c>NativeCULong</c>. Centralized so that the
/// rule (32-bit on Windows or x86, 64-bit on Unix LP64) is expressed once
/// and any future refinement applies everywhere.
/// </summary>
internal static class PlatformLayout
{
    internal static bool Has32BitStorage => IntPtr.Size == 4 || OperatingSystem.IsWindows();
    internal static bool Has64BitStorage => !Has32BitStorage;

    internal static bool NativeIntConstructorCanOverflow => IntPtr.Size != 4 && Has32BitStorage;
    internal static bool NativeIntConstructorCannotOverflow => !NativeIntConstructorCanOverflow;
}
