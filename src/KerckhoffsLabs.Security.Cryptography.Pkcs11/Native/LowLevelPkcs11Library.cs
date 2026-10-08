using System.Runtime.CompilerServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S6640:Using unsafe code blocks is security-sensitive",
    Justification = "This type is the cryptoki dispatch boundary. Its unsafe regions do only what C# permits " +
    "nowhere else: invoke a module function pointer, pin a buffer for the duration of one call, and pass the " +
    "address of a struct as a CK_*_PTR. Every function pointer is checked for NULL before it is invoked, every " +
    "pointer is pinned by a fixed statement scoped to the call or is the address of a local, and every output " +
    "length the module reports is checked against the buffer before a caller sees it. Suppressed at the type " +
    "so that an unsafe block outside this boundary is still reported. Each wrapper is exercised through the " +
    "real function table by the FakeModule smoke tests and LowLevelPkcs11LibraryWrapperContractTests.")]
internal sealed partial class LowLevelPkcs11Library : ILowLevelPkcs11Library
{
    // Why a Windows-layout path is left out of coverage: the reported coverage comes from the Linux
    // test run, where Pkcs11Marshal.IsWindows is false. These paths run in the Windows CI test jobs.
    private const string WindowsOnly = "Windows-only struct layout; exercised by the Windows CI test jobs, which collect no coverage.";

    /// <summary>
    /// The loaded module. It owns the function table, so a call can reach the module only while it holds
    /// a reference on this handle (<see cref="EnterModule"/>), and <c>C_Finalize</c> and the unmap wait
    /// for the last such reference.
    /// </summary>
    private readonly Pkcs11ModuleHandle _module;

    /// <inheritdoc/>
    public Pkcs11ModuleHandle Module => _module;

    /// <summary>
    /// A use of the module for one call. Throws <see cref="ObjectDisposedException"/> once this
    /// library has been disposed; there is no window between that check and the call, because the
    /// use itself keeps the module from being finalized or unmapped.
    /// </summary>
    /// <param name="holdsOffFinalize"><see langword="false"/> only for a blocking <c>C_WaitForSlotEvent</c>.</param>
    private ModuleCall EnterModule(bool holdsOffFinalize = true) => new(_module, holdsOffFinalize);

    /// <summary>What has happened to a requested <c>C_Finalize</c> so far.</summary>
    internal (FinalizeOutcome Outcome, CKR ReturnValue) FinalizeStatus => _module.FinalizeStatus;

    /// <summary>
    /// Loads PKCS#11 library at <paramref name="libraryPath"/> and acquires function
    /// pointers via <c>C_GetFunctionList</c>.
    /// </summary>
    /// <param name="libraryPath">Library name or path.</param>
    public LowLevelPkcs11Library(string libraryPath)
    {
        EnsureCkUlongWidthMatchesPlatform();
        ArgumentException.ThrowIfNullOrEmpty(libraryPath);
        _module = Pkcs11ModuleHandle.Load(libraryPath);
    }

    /// <summary>
    /// Binds to a statically-linked PKCS#11 implementation. The cryptoki symbols are expected to be
    /// linked into the host executable and exported from it, so <c>C_GetFunctionList</c> resolves
    /// against the entry-point module's own symbol table. All subsequent calls go through the
    /// returned function-pointer table, same as the dynamic-load path.
    /// </summary>
    internal LowLevelPkcs11Library()
        : this(() => new Delegates(IntPtr.Zero), Pkcs11ModuleHandle.StaticallyLinked)
    {
    }

    /// <summary>
    /// Binds to a module whose exports come from <paramref name="resolveExport"/> rather than from a
    /// loaded library. This is the test seam: a test hands in a module built from managed
    /// <c>[UnmanagedCallersOnly]</c> functions, and every call then goes through the same loader,
    /// wrappers, pinning and struct packing as a real module.
    /// </summary>
    /// <param name="resolveExport">Maps an export name to its address, or <see cref="IntPtr.Zero"/> when absent.</param>
    internal LowLevelPkcs11Library(Func<string, IntPtr> resolveExport)
        : this(() => new Delegates(resolveExport), resolveExport.Target ?? resolveExport)
    {
    }

    // identity: which module this is, so two bindings of the same one share its Cryptoki state. A test
    // module is identified by the object whose method resolves its exports.
    private LowLevelPkcs11Library(Func<Delegates> bind, object identity)
    {
        EnsureCkUlongWidthMatchesPlatform();
        _module = Pkcs11ModuleHandle.Bind(bind, identity);
    }

    /// <summary>
    /// Verifies the resolved build's CK_ULONG width (<see cref="NativeCULong"/>) matches the
    /// host's native CK_ULONG: 4 bytes on Windows (LLP64), the pointer width on Unix (LP64/ILP32).
    /// KerckhoffsLabs.Runtime.InteropServices ships <see cref="NativeCULong"/> as <c>nuint</c> in its
    /// <c>lib/net10.0</c> assembly and as <c>uint</c> in its <c>runtimes/win-x64</c> and
    /// <c>runtimes/win-arm64</c> assets, so 64-bit Windows running the <c>lib</c> assembly (8 bytes)
    /// would silently mis-marshal every CK_ULONG-bearing struct. Fail loudly instead: the
    /// runtime-specific asset was not resolved.
    /// </summary>
    private static void EnsureCkUlongWidthMatchesPlatform()
    {
        int expected = OperatingSystem.IsWindows() ? sizeof(uint) : IntPtr.Size;
        // Unsafe.SizeOf, not Marshal.SizeOf: what can mis-marshal is the by-value CK_ULONG in the
        // delegate* unmanaged[Cdecl] signatures, and [assembly: DisableRuntimeMarshalling] makes those
        // use the blittable layout. NativeCULong wraps a single primitive so the two sizes agree, but
        // this guard should measure the layout that actually crosses the boundary.
        int actual = Unsafe.SizeOf<NativeCULong>();
        ThrowIfWidthMismatch(actual, expected);
    }

    /// <summary>
    /// The actual throw condition behind <see cref="EnsureCkUlongWidthMatchesPlatform"/>, split out
    /// as a pure function so the mismatch branch is testable without an actually-mismatched build:
    /// a correctly-built test run can never observe <paramref name="actual"/> != <paramref name="expected"/>
    /// from <see cref="EnsureCkUlongWidthMatchesPlatform"/> itself.
    /// </summary>
    internal static void ThrowIfWidthMismatch(int actual, int expected)
    {
        if (actual != expected)
        {
            throw new PlatformNotSupportedException(
                $"CK_ULONG width mismatch: NativeCULong is {actual} bytes but the native CK_ULONG on " +
                $"this platform is {expected} bytes. The runtime-specific KerckhoffsLabs.Runtime.InteropServices " +
                "assembly for this platform was not loaded. Deploy the application's .deps.json with it, or " +
                "restore and publish with a RuntimeIdentifier, and check that no version of " +
                "KerckhoffsLabs.Runtime.InteropServices older than 1.2.0 is referenced or overrides it.");
        }
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD
    /// functions (C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal +
    /// matching Decrypt variants). False on v2.40 libraries.
    /// </summary>
    public bool IsMessageApiSupported
        => _module.Table.HasC_MessageEncryptInit
           && _module.Table.HasC_EncryptMessage
           && _module.Table.HasC_MessageEncryptFinal
           && _module.Table.HasC_MessageDecryptInit
           && _module.Table.HasC_DecryptMessage
           && _module.Table.HasC_MessageDecryptFinal;

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.2 surface (ML-KEM
    /// encapsulate/decapsulate, authenticated wrap/unwrap, signature-only verify, and
    /// validation-flags inspection). False on v2.40 / v3.0 / v3.1 libraries.
    /// </summary>
    public unsafe bool IsV32ApiSupported
        => _module.Table._fp.C_EncapsulateKey is not null
           && _module.Table._fp.C_DecapsulateKey is not null
           && _module.Table._fp.C_WrapKeyAuthenticated is not null
           && _module.Table._fp.C_UnwrapKeyAuthenticated is not null
           && _module.Table._fp.C_VerifySignatureInit is not null
           && _module.Table._fp.C_VerifySignature is not null
           && _module.Table._fp.C_GetSessionValidationFlags is not null;

    /// <summary>
    /// Asks for <c>C_Finalize</c> on the module's last release instead of now. A call still in flight, or
    /// a session still open, holds a reference, so the module is finalized only once nothing is using it.
    /// Has no effect unless <c>C_Initialize</c> through this library succeeded.
    /// </summary>
    public void FinalizeOnLastRelease() => _module.FinalizeOnRelease();

    /// <summary>
    /// Releases this library's reference on the module. Calls that begin afterwards throw
    /// <see cref="ObjectDisposedException"/>; one already in flight completes, and the module is
    /// finalized (if requested) and unmapped when it, and every session, has released its reference.
    /// </summary>
    public void Dispose() => _module.Dispose();
}
