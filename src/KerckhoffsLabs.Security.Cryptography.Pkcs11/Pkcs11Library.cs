using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// High level PKCS#11 wrapper.
/// </summary>
/// <remarks>
/// <para><b>Lifetime contract:</b> the <see cref="Pkcs11Library"/> must outlive every
/// <c>Pkcs11Session</c> and <see cref="Pkcs11Workspace"/> it produces. Disposing the library
/// while sessions are open is supported as a safety net — <see cref="Dispose()"/> closes
/// every tracked session before <c>C_Finalize</c> — but is not a substitute for orderly
/// cleanup. Failure to dispose sessions first is a caller bug that delays graceful release.</para>
/// </remarks>
public sealed class Pkcs11Library : IDisposable
{
    private bool _disposed;

    private readonly ILogger _logger;

    /// <summary>
    /// The factory this instance was constructed with, or <see langword="null"/> when none was
    /// given and the instance does not log. Handed down to every <see cref="Pkcs11Slot"/> and
    /// <c>Pkcs11Session</c> this library produces, so a whole library/slot/session chain shares one
    /// logging setup, configured per instance — there is no process-wide logging state.
    /// </summary>
    private readonly ILoggerFactory? _loggerFactory;

    private readonly string? _libraryPath;

    private LowLevelPkcs11Library? _pkcs11Library;

    /// <summary>
    /// The loaded low-level library. Set during construction and released on
    /// <see cref="Dispose()"/>; accessing it afterwards throws.
    /// </summary>
    private LowLevelPkcs11Library LowLevel => _pkcs11Library
        ?? throw new ObjectDisposedException(nameof(Pkcs11Library));

    /// <summary>
    /// Test seam: access to the underlying low-level wrapper for regression checks on
    /// session tracking. Not exposed publicly.
    /// </summary>
    internal LowLevelPkcs11Library? LowLevelLibrary => _pkcs11Library;

    /// <summary>
    /// Cached per-token quirk for ML-KEM decapsulation: whether the shared-secret template must
    /// omit <c>CKA_VALUE_LEN</c>. Tokens disagree on the unwrap-created key — SoftHSM rejects
    /// <c>CKA_VALUE_LEN</c> as read-only, opencryptoki requires it — and PKCS#11 offers no way to
    /// query this, so it is learned the first time <see cref="Algorithms.MLKemPkcs11"/> decapsulates
    /// against this token and reused thereafter. <c>null</c> until probed; constant for a given module.
    /// </summary>
    internal bool? MlKemDecapsulateOmitsValueLen { get; set; }

    /// <summary>
    /// Loads and initializes the PKCS#11 library at <paramref name="libraryPath"/>.
    /// Function pointers are acquired via <c>C_GetFunctionList</c> (the PKCS#11
    /// v2.20+ recommended path).
    /// </summary>
    /// <param name="libraryPath">Library name or path.</param>
    /// <param name="loggerFactory">
    /// Logger factory for this instance and every <see cref="Pkcs11Slot"/>/<c>Pkcs11Session</c> it
    /// produces. Pass <see langword="null"/> (the default) for no logging. This is the only way to
    /// configure the library's logging, so independent consumers in the same process each configure
    /// their own <see cref="Pkcs11Library"/> instance.
    /// </param>
    /// <returns>A loaded, initialized <see cref="Pkcs11Library"/> bound to the module at <paramref name="libraryPath"/>.</returns>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Initialize</c> call.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0027:API with optional parameter(s) should have the most parameters amongst its public overloads", Justification = "The options overload differs in the second parameter's type (Pkcs11LibraryOptions vs. ILoggerFactory) and has no optional parameters, so Load(path) binds only here and no call site binds ambiguously.")]
    public static Pkcs11Library Load(string libraryPath, ILoggerFactory? loggerFactory = null)
        => new(libraryPath, () => new LowLevelPkcs11Library(libraryPath), loggerFactory, options: null);

    /// <summary>
    /// Loads and initializes the PKCS#11 library at <paramref name="libraryPath"/> with
    /// <paramref name="options"/> — for a module that needs a configuration string in
    /// <c>C_Initialize</c>, such as NSS softoken before 3.52.
    /// </summary>
    /// <param name="libraryPath">Library name or path.</param>
    /// <param name="options">Logging and module-specific initialization settings; see <see cref="Pkcs11LibraryOptions"/>.</param>
    /// <returns>A loaded, initialized <see cref="Pkcs11Library"/> bound to the module at <paramref name="libraryPath"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Initialize</c> call.</exception>
    public static Pkcs11Library Load(string libraryPath, Pkcs11LibraryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new(libraryPath, () => new LowLevelPkcs11Library(libraryPath), options.LoggerFactory, options);
    }

    /// <summary>
    /// Binds to a PKCS#11 implementation that is statically linked into the host
    /// executable, rather than dynamically loaded from a path. Use this entry
    /// point on platforms where dynamic library loading is unavailable or
    /// restricted (Native AOT, single-file embedded builds).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The host executable must export the cryptoki <c>C_GetFunctionList</c> symbol from its
    /// entry-point module: resolution goes through that module's own <i>dynamic</i> symbol table,
    /// which behaves the same on CoreCLR and Native AOT. There is no <c>"__Internal"</c>
    /// pseudo-library involved — that is a Mono-only convention no runtime this package targets
    /// implements.
    /// </para>
    /// <para>
    /// Under Native AOT, linking the module in is not by itself enough, and both extra steps are
    /// easy to miss because each fails silently into the same "entry point not found":
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     A static archive contributes only the members that resolve an undefined reference, and
    ///     nothing in a managed binary references the bootstrap by name. Force the member in — GNU
    ///     ld <c>--undefined=C_GetFunctionList</c>, Apple <c>-u _C_GetFunctionList</c> — or link the
    ///     object file directly.
    ///   </description></item>
    ///   <item><description>
    ///     ILC generates an exports file that keeps only its own symbol
    ///     (<c>global: DotNetRuntimeDebugHeader; local: *;</c>) and hands it to the linker, so the
    ///     symbol stays hidden no matter what export flags are also passed. Add
    ///     <c>C_GetFunctionList</c> to that exports file.
    ///   </description></item>
    /// </list>
    /// <para>
    /// All subsequent PKCS#11 calls go through the function-pointer table returned by that single
    /// call — no other unmanaged bindings are required. The v3.0/v3.2 surface is bound
    /// best-effort from the same symbol table, exactly as for a dynamically loaded module.
    /// </para>
    /// <para>
    /// What counts as reachable through the entry-point module is the platform's business, not this
    /// library's, and the platforms differ. A dynamically loaded module's symbols stay private to it
    /// on Linux, but macOS resolves more permissively: in a process that has already loaded a PKCS#11
    /// module by path, this method can bind <i>that</i> module rather than failing. Use
    /// <see cref="Load(string, ILoggerFactory?)"/> when you mean a specific module.
    /// </para>
    /// </remarks>
    /// <param name="loggerFactory">
    /// Logger factory for this instance and every <see cref="Pkcs11Slot"/>/<c>Pkcs11Session</c> it
    /// produces. Pass <see langword="null"/> (the default) for no logging.
    /// </param>
    /// <returns>A loaded, initialized <see cref="Pkcs11Library"/> bound to the statically linked module.</returns>
    /// <exception cref="EntryPointNotFoundException">
    /// The host executable does not export <c>C_GetFunctionList</c>.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Initialize</c> call.</exception>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0027:API with optional parameter(s) should have the most parameters amongst its public overloads", Justification = "The options overload differs in the parameter's type (Pkcs11LibraryOptions vs. ILoggerFactory) and has no optional parameters, so LoadStaticallyLinked() binds only here and no call site binds ambiguously.")]
    public static Pkcs11Library LoadStaticallyLinked(ILoggerFactory? loggerFactory = null)
        => new(libraryPath: "<statically-linked>", () => new LowLevelPkcs11Library(), loggerFactory, options: null);

    /// <summary>
    /// Binds to the PKCS#11 implementation statically linked into the host executable, as
    /// <see cref="LoadStaticallyLinked(ILoggerFactory?)"/> does, and initializes it with
    /// <paramref name="options"/> — for a linked-in module that needs, say, a configuration string in
    /// <c>C_Initialize</c>.
    /// </summary>
    /// <remarks>Every requirement and caveat of <see cref="LoadStaticallyLinked(ILoggerFactory?)"/> applies.</remarks>
    /// <param name="options">Logging and module-specific initialization settings; see <see cref="Pkcs11LibraryOptions"/>.</param>
    /// <returns>A loaded, initialized <see cref="Pkcs11Library"/> bound to the statically linked module.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    /// <exception cref="EntryPointNotFoundException">
    /// The host executable does not export <c>C_GetFunctionList</c>.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Initialize</c> call.</exception>
    public static Pkcs11Library LoadStaticallyLinked(Pkcs11LibraryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new(libraryPath: "<statically-linked>", () => new LowLevelPkcs11Library(), options.LoggerFactory, options);
    }

    /// <summary>
    /// Test seam: binds to a module whose exports come from <paramref name="resolveExport"/> (a fake
    /// module built from managed <c>[UnmanagedCallersOnly]</c> functions), then initializes it exactly
    /// as <see cref="Load(string, ILoggerFactory?)"/> does. Every call crosses the real loader, wrappers,
    /// pinning and struct packing.
    /// </summary>
    internal Pkcs11Library(Func<string, IntPtr> resolveExport, ILoggerFactory? loggerFactory = null, Pkcs11LibraryOptions? options = null)
        : this(libraryPath: "<fake module>", () => new LowLevelPkcs11Library(resolveExport), loggerFactory, options)
    {
    }

    private Pkcs11Library(string libraryPath, Func<LowLevelPkcs11Library> load, ILoggerFactory? loggerFactory, Pkcs11LibraryOptions? options)
    {
        _loggerFactory = loggerFactory;
        _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<Pkcs11Library>();
        Log.LibraryTrace(_logger, libraryPath, "ctor");

        _libraryPath = libraryPath;

        try
        {
            Log.LoadingLibrary(_logger, _libraryPath);
            _pkcs11Library = load();
            Initialize(options);
        }
        catch
        {
            if (_pkcs11Library != null)
            {
                Log.UnloadingLibrary(_logger, _libraryPath);
                _pkcs11Library.Dispose();
                _pkcs11Library = null;
            }

            throw;
        }
    }

    /// <summary>
    /// Initializes the PKCS#11 library. Probes with <c>CKF_OS_LOCKING_OK</c>
    /// first (the safe default for multi-threaded callers); falls back to a
    /// call without it if the token returns <c>CKR_CANT_LOCK</c>. With
    /// <see cref="Pkcs11LibraryOptions.UseOsLocking"/> off, makes only the call without it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Per PKCS#11 v3.1 §5.4, a token may refuse <c>CKF_OS_LOCKING_OK</c>; the
    /// spec calls out <c>CKR_CANT_LOCK</c> as the expected return code in that
    /// case. The fallback path uses <c>pInitArgs = NULL</c>, which declares the
    /// application will not access the library from multiple threads
    /// concurrently. This library keeps that promise itself: every call into such a
    /// module is serialized (see <see cref="SupportsConcurrentAccess"/>).
    /// </para>
    /// <para>
    /// <paramref name="options"/> adds to both calls: <see cref="Pkcs11LibraryOptions.ModuleParameters"/>
    /// in <c>pReserved</c>, and <c>CKF_LIBRARY_CANT_CREATE_OS_THREADS</c> for
    /// <see cref="Pkcs11LibraryOptions.CantCreateOsThreads"/>. Either makes the call without OS locking
    /// pass arguments without <c>CKF_OS_LOCKING_OK</c> and with no mutex callbacks instead of
    /// <c>NULL</c> — which the standard defines as the same single-threaded declaration.
    /// </para>
    /// </remarks>
    private void Initialize(Pkcs11LibraryOptions? options)
    {
        Log.LibraryTrace(_logger, _libraryPath, "Initialize");

        ulong threadFlags = options is { CantCreateOsThreads: true } ? CKF.CKF_LIBRARY_CANT_CREATE_OS_THREADS : 0;
        IntPtr reserved = AllocateModuleParameters(options?.ModuleParameters);
        try
        {
            // Without OS locking: NULL when there is nothing else to pass, which every module must accept.
            // Either way it promises the module it is never called concurrently, and the module handle
            // serializes every call to keep the promise.
            CK_C_INITIALIZE_ARGS? withoutOsLocking = reserved == IntPtr.Zero && threadFlags == 0
                ? null
                : new CK_C_INITIALIZE_ARGS { Flags = (NativeCULong)threadFlags, Reserved = reserved };

            CKR rv;
            if (options is { UseOsLocking: false })
            {
                rv = LowLevel.C_Initialize(withoutOsLocking);
            }
            else
            {
                rv = LowLevel.C_Initialize(new CK_C_INITIALIZE_ARGS { Flags = (NativeCULong)(CKF.CKF_OS_LOCKING_OK | threadFlags), Reserved = reserved });

                // Token refused OS locking. Retry without.
                if (rv == CKR.CKR_CANT_LOCK)
                {
                    _logger.LogWarning(
                        "PKCS#11 library {LibraryPath} refused CKF_OS_LOCKING_OK; retrying without OS locking, and serializing every call into it",
                        _libraryPath);
                    rv = LowLevel.C_Initialize(withoutOsLocking);
                }
            }

            // Another component already initialized the library: treat as success. The module handle owes
            // C_Finalize only for an initialization it performed, so Dispose leaves their state alone.
            if (rv == CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED) return;

            Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpInitialize);
        }
        finally
        {
            // Zeroed on free: some modules take credentials in their parameter string.
            UnmanagedMemory.Free(ref reserved);
        }
    }

    /// <summary>
    /// Copies <paramref name="moduleParameters"/> into a NUL-terminated UTF-8 block for
    /// <c>pReserved</c>, or returns <see cref="IntPtr.Zero"/> when there are none. The caller frees it.
    /// </summary>
    private static IntPtr AllocateModuleParameters(string? moduleParameters)
    {
        if (moduleParameters is null)
            return IntPtr.Zero;

        // Pkcs11LibraryOptions refused anything that does not encode exactly, so this cannot substitute.
        byte[] utf8 = Encoding.UTF8.GetBytes(moduleParameters);
        try
        {
            // Allocate zero-fills, so the extra byte is the terminator.
            IntPtr block = UnmanagedMemory.Allocate(utf8.Length + 1);
            UnmanagedMemory.Write(block, utf8);
            return block;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    /// <summary>
    /// Gets general information about loaded PKCS#11 library
    /// </summary>
    /// <returns>General information about loaded PKCS#11 library</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetInfo</c> call.</exception>
    public LibraryInfo GetInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "GetInfo");

        CK_INFO info = new();
        CKR rv = LowLevel.C_GetInfo(ref info);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetInfo);

        return new LibraryInfo(info);
    }

    /// <summary>
    /// Whether the module reports a Cryptoki interface version of at least <paramref name="version"/>
    /// — the readable form of <c>GetInfo().CryptokiVersion &gt;= version</c>, and the
    /// supported alternative to driving version detection off a <c>CKR_FUNCTION_NOT_SUPPORTED</c>
    /// exception from <see cref="GetInterfaces"/>.
    /// </summary>
    /// <remarks>
    /// This is what the module claims to be *compatible with*, not which function tables actually
    /// bound: a module may report 3.2 and still refuse an individual v3.2 entry point. Pass the version
    /// as the PKCS#11 headers define it (<c>CRYPTOKI_VERSION_MAJOR</c>, <c>CRYPTOKI_VERSION_MINOR</c>):
    /// v2.40 is <c>new Version(2, 40)</c>, but v3.0, v3.1 and v3.2 are <c>new Version(3, 0)</c>,
    /// <c>(3, 1)</c> and <c>(3, 2)</c>, not <c>(3, 10)</c> or <c>(3, 20)</c>. Queries the module on
    /// every call.
    /// </remarks>
    /// <param name="version">
    /// Required version, major and minor only: <c>new Version(3, 1)</c> for v3.1. <c>CK_VERSION</c> has no
    /// build or revision number.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="version"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="version"/> sets a build or revision number. The reported version never has one, and
    /// <see cref="Version"/> orders an unset build below <c>0</c>, so <c>new Version(3, 1, 0)</c> would read
    /// as newer than every v3.1 module.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetInfo</c> call.</exception>
    public bool SupportsCryptokiVersion(Version version)
    {
        ArgumentNullException.ThrowIfNull(version);
        if (version.Build != -1 || version.Revision != -1)
            throw new ArgumentException(
                "CK_VERSION has only a major and a minor number; pass new Version(major, minor).", nameof(version));

        return GetInfo().CryptokiVersion >= version;
    }

    /// <summary>
    /// Obtains a list of slots in the system.
    /// </summary>
    /// <param name="tokenPresent">
    /// When <c>true</c> (the default), returns only slots that currently have a token
    /// inserted. When <c>false</c>, returns all slots regardless of token presence —
    /// useful for diagnostic enumeration.
    /// </param>
    /// <returns>Read-only list of available slots.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_GetSlotList</c> call.</exception>
    public IReadOnlyList<Pkcs11Slot> GetSlotList(bool tokenPresent = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "GetSlotList");

        CKR rv = LowLevel.C_GetSlotList(tokenPresent, [], out NativeCULong slotCount);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetSlotList);

        if (slotCount.Value == 0)
            return [];

        NativeCULong[] slotList = new NativeCULong[ReportedLength.ForAllocation(slotCount, Pkcs11Operations.OpGetSlotList)];
        rv = LowLevel.C_GetSlotList(tokenPresent, slotList, out slotCount);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetSlotList);

        // A slot removed between the two calls lowers the count; one added is CKR_BUFFER_TOO_SMALL.
        slotList = ReportedLength.Items(slotList, slotCount, Pkcs11Operations.OpGetSlotList);

        List<Pkcs11Slot> list = [];
        foreach (NativeCULong slot in slotList)
            list.Add(new Pkcs11Slot(LowLevel, (ulong)slot, _loggerFactory));

        return list;
    }

    /// <summary>
    /// Enumerates the interfaces this module exposes (PKCS#11 v3.0 <c>C_GetInterfaceList</c>) —
    /// the standard <c>"PKCS 11"</c> interface plus any vendor-specific ones. This is the only way
    /// to discover vendor interface tables a token offers.
    /// </summary>
    /// <returns>The interface descriptors, or an empty list if the module reports none.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">
    /// Thrown with <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 modules, which have no
    /// interface concept.
    /// </exception>
    public IReadOnlyList<InterfaceInfo> GetInterfaces()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "GetInterfaces");

        NativeCULong count = new(0);
        CKR rv = LowLevel.C_GetInterfaceList(null, ref count);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetInterfaceList);

        if (count.Value == 0)
            return [];

        CK_INTERFACE[] raw = new CK_INTERFACE[ReportedLength.ForAllocation(count, Pkcs11Operations.OpGetInterfaceList)];
        rv = LowLevel.C_GetInterfaceList(raw, ref count);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetInterfaceList);

        int n = ReportedLength.Written(count, raw.Length, Pkcs11Operations.OpGetInterfaceList);
        List<InterfaceInfo> list = new(n);
        for (int i = 0; i < n; i++)
        {
            string name = raw[i].InterfaceName != IntPtr.Zero
                ? Marshal.PtrToStringUTF8(raw[i].InterfaceName) ?? string.Empty
                : string.Empty;
            list.Add(new InterfaceInfo(name, (ulong)raw[i].Flags));
        }

        return list;
    }

    /// <summary>
    /// Obtains a single interface descriptor by name (PKCS#11 v3.0 <c>C_GetInterface</c>) — a direct
    /// lookup, versus enumerating every interface with <see cref="GetInterfaces"/>.
    /// </summary>
    /// <param name="interfaceName">The interface name to request (e.g. <c>"PKCS 11"</c>), or <c>null</c> for the module's default interface.</param>
    /// <returns>The matching interface descriptor.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">
    /// Thrown with <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 modules (which have no interface
    /// concept), or with the token's error code when the named interface is not available.
    /// </exception>
    public InterfaceInfo GetInterface(string? interfaceName = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "GetInterface");

        // pInterfaceName is a NUL-terminated C string; null requests the module's default interface.
        byte[]? nameBytes = interfaceName is null ? null : Encoding.UTF8.GetBytes(interfaceName + '\0');
        CKR rv = LowLevel.C_GetInterface(nameBytes, new NativeCULong(0), out CK_INTERFACE iface);
        Pkcs11Exception.ThrowIfError(rv, Pkcs11Operations.OpGetInterface);

        string name = iface.InterfaceName != IntPtr.Zero
            ? Marshal.PtrToStringUTF8(iface.InterfaceName) ?? string.Empty
            : string.Empty;
        return new InterfaceInfo(name, (ulong)iface.Flags);
    }

    /// <summary>
    /// Whether the module may be called from several threads at once: it accepted OS locking
    /// (<c>CKF_OS_LOCKING_OK</c>) when it was initialized, by this instance or another instance loaded from
    /// the same module.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see langword="false"/> when the module refused OS locking (<c>CKR_CANT_LOCK</c>) and was initialized
    /// without it, which promises it is never called concurrently (PKCS#11 v3.2 §5.4). This library keeps
    /// that promise: every call into the module, from every instance and session using it, is serialized,
    /// so it stays correct to use from several threads, but those calls run one at a time. Also
    /// <see langword="false"/> when the module was initialized by something other than this library, whose
    /// threading mode cannot be known.
    /// </para>
    /// <para>
    /// A blocking <see cref="WaitForSlotEvent"/> is refused when this is <see langword="false"/>.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    public bool SupportsConcurrentAccess
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return LowLevel.Module.SupportsConcurrentAccess;
        }
    }

    /// <summary>
    /// Waits for a slot event, such as token insertion or token removal, to occur.
    /// </summary>
    /// <param name="nonBlocking">
    /// When <c>true</c>, returns immediately even if no event is pending (the result will be
    /// <see langword="null"/>). When <c>false</c>, blocks until an event occurs.
    /// </param>
    /// <returns>
    /// The PKCS#11 handle of the slot the event occurred in, or <see langword="null"/> if no event
    /// occurred — only possible when <paramref name="nonBlocking"/> is <see langword="true"/>.
    /// </returns>
    /// <remarks>
    /// A blocking wait needs a module that may be called concurrently (<see cref="SupportsConcurrentAccess"/>):
    /// otherwise it would hold the module's only lock until an event came, keeping out every other call,
    /// and <see cref="Dispose"/> could not wake it. Poll with <paramref name="nonBlocking"/> there instead.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <paramref name="nonBlocking"/> is <see langword="false"/>
    /// and <see cref="SupportsConcurrentAccess"/> is <see langword="false"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_WaitForSlotEvent</c> call.</exception>
    public ulong? WaitForSlotEvent(bool nonBlocking)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!nonBlocking && !SupportsConcurrentAccess)
            throw new InvalidOperationException(
                "A blocking WaitForSlotEvent needs a module that may be called concurrently, and this one may not " +
                "(see SupportsConcurrentAccess). Poll with nonBlocking: true instead.");

        Log.LibraryTrace(_logger, _libraryPath, "WaitForSlotEvent");

        NativeCULong flags = (NativeCULong)(nonBlocking ? CKF.CKF_DONT_BLOCK : 0UL);
        NativeCULong slotIdOut = new(0);
        CKR rv = LowLevel.C_WaitForSlotEvent(flags, ref slotIdOut, IntPtr.Zero);

        if (rv == CKR.CKR_OK) return (ulong)slotIdOut;

        // CKR_NO_EVENT is expected in non-blocking mode when nothing's pending.
        if (nonBlocking && rv == CKR.CKR_NO_EVENT) return null;

        throw Pkcs11Exception.Create(rv, Pkcs11Operations.OpWaitForSlotEvent);
    }

    /// <summary>
    /// Opens an authenticated workspace against the slot whose token label matches
    /// <paramref name="slotLabel"/>.
    /// </summary>
    /// <param name="slotLabel">The token label (case-sensitive, trimmed of trailing
    /// spaces — PKCS#11 pads labels with spaces to 32 chars).</param>
    /// <param name="userType">The PKCS#11 user type to log in as.</param>
    /// <param name="pin">The PIN. The workspace does not retain the PIN past construction.</param>
    /// <param name="policy">The crypto policy the workspace enforces. <see langword="null"/> means
    /// <see cref="CryptoPolicy.SecureOnly"/>. See <see cref="ICryptoPolicy"/>.</param>
    /// <returns>An open <see cref="Pkcs11Workspace"/>. Callers must <c>Dispose</c> it.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="slotLabel"/> or <paramref name="pin"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if no slot with a matching token label is present.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying PKCS#11 calls.</exception>
    public Pkcs11Workspace OpenWorkspaceWithPin(string slotLabel, CKU userType, SecurePin pin, ICryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(slotLabel);
        ArgumentNullException.ThrowIfNull(pin);

        Pkcs11Slot matched = MatchSlotByLabel(slotLabel);
        var session = matched.OpenSession(policy: policy);
        try
        {
            session.Login(userType, pin);
            return new Pkcs11Workspace(this, matched, session);
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens an authenticated workspace against the slot whose token label matches
    /// <paramref name="slotLabel"/>, logging in via the token's own pinpad rather than an
    /// application-supplied PIN. For tokens advertising <see cref="TokenFlags.ProtectedAuthenticationPath"/>
    /// — the PIN is entered on the device itself, and PKCS#11 signals this to the token by calling
    /// <c>C_Login</c> with <c>pPin = NULL_PTR</c>. Calling this on a token without that flag typically
    /// fails with <see cref="CKR.CKR_ARGUMENTS_BAD"/> or <see cref="CKR.CKR_PIN_INCORRECT"/>.
    /// </summary>
    /// <param name="slotLabel">The token label (case-sensitive, trimmed of trailing
    /// spaces — PKCS#11 pads labels with spaces to 32 chars).</param>
    /// <param name="userType">The PKCS#11 user type to log in as.</param>
    /// <param name="policy">The crypto policy the workspace enforces. <see langword="null"/> means
    /// <see cref="CryptoPolicy.SecureOnly"/>. See <see cref="ICryptoPolicy"/>.</param>
    /// <returns>An open <see cref="Pkcs11Workspace"/>. Callers must <c>Dispose</c> it.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="slotLabel"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if no slot with a matching token label is present.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying PKCS#11 calls.</exception>
    public Pkcs11Workspace OpenWorkspaceWithPinpad(string slotLabel, CKU userType, ICryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(slotLabel);

        Pkcs11Slot matched = MatchSlotByLabel(slotLabel);
        var session = matched.OpenSession(policy: policy);
        try
        {
            session.Login(userType);
            return new Pkcs11Workspace(this, matched, session);
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Opens a workspace against the slot whose token label matches <paramref name="slotLabel"/>
    /// <em>without</em> logging in. For tokens that do not require authentication — the token's
    /// <c>CKF_LOGIN_REQUIRED</c> flag is clear (e.g. a software token's public crypto services) —
    /// where a <c>C_Login</c> call would be rejected with <see cref="CKR.CKR_USER_TYPE_INVALID"/>.
    /// Only public and session objects are reachable, which is sufficient for stateless crypto
    /// (hashing, and operations on session-lifetime keys).
    /// </summary>
    /// <param name="slotLabel">The token label (case-sensitive, trimmed of trailing spaces).</param>
    /// <param name="policy">The crypto policy the workspace enforces. <see langword="null"/> means
    /// <see cref="CryptoPolicy.SecureOnly"/>. See <see cref="ICryptoPolicy"/>.</param>
    /// <returns>An open <see cref="Pkcs11Workspace"/>. Callers must <c>Dispose</c> it.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="slotLabel"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if no slot with a matching token label is present.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_OpenSession</c> call.</exception>
    public Pkcs11Workspace OpenWorkspaceWithoutLogin(string slotLabel, ICryptoPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(slotLabel);

        Pkcs11Slot matched = MatchSlotByLabel(slotLabel);
        var session = matched.OpenSession(policy: policy);
        try
        {
            return new Pkcs11Workspace(this, matched, session);
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    private Pkcs11Slot MatchSlotByLabel(string slotLabel)
        => GetSlotList()
            .FirstOrDefault(slot => slot.GetTokenInfo().Label.TrimEnd() == slotLabel)
            ?? throw new ArgumentException(
                $"No slot found with token label '{slotLabel}'.", nameof(slotLabel));

    #region IDisposable

    /// <summary>
    /// Releases the library: closes any sessions still tracked against it, and releases the module.
    /// <c>C_Finalize</c> (only if this instance drove <c>C_Initialize</c>) and the unmap run when the
    /// last use of the module goes: at once, or when a call still in flight on another thread returns.
    /// A thread blocked in <see cref="WaitForSlotEvent"/> does not delay <c>C_Finalize</c>; it is woken
    /// with <c>CKR_CRYPTOKI_NOT_INITIALIZED</c>, as PKCS#11 specifies. While another load of the same
    /// module is still live, <c>C_Finalize</c> waits for that one too, since they share the module's
    /// state. It therefore runs on whichever thread releases the last use. Dispose logs what it can know
    /// of it: a failure when it ran at once, or that it was deferred or left to another load. There is no finalizer — the native module is released by
    /// <c>Pkcs11ModuleHandle</c>'s critical-finalizer <see cref="SafeHandle"/>
    /// if a caller forgets to dispose.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        Log.LibraryTrace(_logger, _libraryPath, "Dispose");

        if (_pkcs11Library != null)
        {
            // Close any session handles still alive against this library before
            // C_Finalize tears down the cryptoki state — otherwise a stray
            // Pkcs11SessionHandle finalizer would call C_CloseSession through a
            // function table whose backing module has been unmapped. The
            // ownership contract is: the library MUST outlive every session it
            // produced. This is the safety net for callers that violate it.
            _pkcs11Library.Module.CloseAllTrackedSessions();

            // A no-op unless THIS instance drove C_Initialize to CKR_OK: after
            // CKR_CRYPTOKI_ALREADY_INITIALIZED another owner is responsible for
            // finalization, and doing it here would tear down their state. The finalize
            // is deferred to the module's last release, so it cannot run under a call
            // that is still in flight on another thread.
            _pkcs11Library.FinalizeOnLastRelease();

            Log.UnloadingLibrary(_logger, _libraryPath);
            var loaded = _pkcs11Library;
            loaded.Dispose();
            _pkcs11Library = null;
            _disposed = true;

            // After the state change, so a logger that throws cannot leave the library half disposed.
            LogFinalizeStatus(loaded.FinalizeStatus);
        }

        _disposed = true;
    }

    // C_Finalize runs on whichever thread releases the module last (see Pkcs11ModuleHandle), which
    // never logs: this reports what Dispose itself can know.
    private void LogFinalizeStatus((FinalizeOutcome Outcome, CKR ReturnValue) status)
    {
        switch (status.Outcome)
        {
            case FinalizeOutcome.Failed:
                Log.FinalizeFailed(_logger, _libraryPath, status.ReturnValue);
                break;
            case FinalizeOutcome.Deferred:
                Log.FinalizeDeferred(_logger, _libraryPath);
                break;
            case FinalizeOutcome.HandedOff:
                Log.FinalizeHandedOff(_logger, _libraryPath);
                break;
        }
    }

    #endregion
}
