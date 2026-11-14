using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// High level PKCS#11 wrapper.
/// </summary>
/// <remarks>
/// <para><b>Lifetime contract:</b> the <see cref="Pkcs11Library"/> must outlive every
/// <c>Pkcs11SessionCore</c> and <see cref="Pkcs11Session"/> it produces. Disposing the library
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
    /// <c>Pkcs11SessionCore</c> this library produces, so a whole library/slot/session chain shares one
    /// logging setup, configured per instance — there is no process-wide logging state.
    /// </summary>
    private readonly ILoggerFactory? _loggerFactory;

    private readonly string? _libraryPath;

    /// <summary>The curve catalog from <see cref="Pkcs11LibraryOptions.CurveCatalog"/>, shared by every session.</summary>
    internal Pkcs11CurveCatalog CurveCatalog { get; }

    private LowLevelPkcs11Library? _pkcs11Library;

    // This library's share of its module's slot events; ended first thing in Dispose.
    private SlotEventSubscription? _slotEvents;

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

    /// <summary>Whether <see cref="Dispose"/> has run.</summary>
    internal bool IsDisposed => Volatile.Read(ref _disposed);

    // Set first thing in Dispose, before this library's login holds are released, so a hold cannot be added after
    // that release (see TokenLoginRecord.AddHolderLocked).
    private int _disposing;

    /// <summary>
    /// Whether <see cref="Dispose"/> has started: from then on no login hold can be taken through this library.
    /// </summary>
    internal bool IsDisposingOrDisposed => Volatile.Read(ref _disposing) != 0 || IsDisposed;

    /// <summary>
    /// Test seam: marks this library disposing, as the first step of <see cref="Dispose"/> does, without going on to
    /// release anything, so a test can stand in the instant between that mark and the release of the library's holds.
    /// A later <see cref="Dispose"/> runs in full.
    /// </summary>
    internal void BeginDisposingForTest() => Volatile.Write(ref _disposing, 1);

    /// <summary>The logger factory from <see cref="Pkcs11LibraryOptions.LoggerFactory"/>, for what this library opens.</summary>
    internal ILoggerFactory? LoggerFactory => _loggerFactory;

    /// <summary>
    /// Cached per-token quirk for ML-KEM decapsulation: whether the shared-secret template must
    /// omit <c>CKA_VALUE_LEN</c>. Tokens disagree on the unwrap-created key — SoftHSM rejects
    /// <c>CKA_VALUE_LEN</c> as read-only, opencryptoki requires it — and PKCS#11 offers no way to
    /// query this, so it is learned the first time <see cref="Algorithms.MLKemPkcs11"/> decapsulates
    /// against this token and reused thereafter. <see langword="null"/> until probed; constant for a given module.
    /// </summary>
    internal bool? MlKemDecapsulateOmitsValueLen { get; set; }

    /// <summary>
    /// Loads and initializes the PKCS#11 library at <paramref name="libraryPath"/>.
    /// Function pointers are acquired via <c>C_GetFunctionList</c> (the PKCS#11
    /// v2.20+ recommended path).
    /// </summary>
    /// <param name="libraryPath">
    /// Path of the module. Prefer a fully qualified path from trusted configuration, such as
    /// <c>/usr/lib/softhsm/libsofthsm2.so</c>: it is loaded exactly as given, and a module's initializers run
    /// as soon as it is loaded. The other two forms load as the OS would load them, with one restriction:
    /// <list type="bullet">
    ///   <item><description>
    ///     A bare name (<c>libsofthsm2.so</c>, <c>cryptoki.dll</c>) is searched for in this library's
    ///     directory and the system's library directories, never in the current directory, where a planted
    ///     module could win. On Windows <c>PATH</c> is excluded too. On Linux an empty entry in
    ///     <c>LD_LIBRARY_PATH</c> (a stray <c>:</c>) would still make <c>dlopen</c> look there. On macOS, whose
    ///     loader would search the current directory, the name is resolved here against the application's
    ///     native-asset directories, the application directory, <c>DYLD_LIBRARY_PATH</c> and dyld's fallback
    ///     directories instead, trying the <c>lib</c> prefix and <c>.dylib</c> suffix as .NET does elsewhere.
    ///   </description></item>
    ///   <item><description>
    ///     A relative path with a directory part (<c>modules/libx.so</c>) is resolved against the current
    ///     directory only, on every OS (Windows' loader would also try it under each directory of its search),
    ///     so where the process starts decides what loads. It loads, and a warning is logged.
    ///   </description></item>
    /// </list>
    /// </param>
    /// <param name="options">
    /// Logging and module-specific initialization settings; see <see cref="Pkcs11LibraryOptions"/>.
    /// Pass <see langword="null"/> (the default) for no logging and a standard initialization. Logging
    /// is configured only here, per instance, so independent consumers in the same process each
    /// configure their own <see cref="Pkcs11Library"/>.
    /// </param>
    /// <returns>A loaded, initialized <see cref="Pkcs11Library"/> bound to the module at <paramref name="libraryPath"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="libraryPath"/> is <see langword="null"/> or empty.</exception>
    /// <exception cref="DllNotFoundException">
    /// The module was not found where <paramref name="libraryPath"/> says to look, or was found but could not be
    /// loaded (a missing dependency, for example). For a bare name the message says the current directory was
    /// not searched.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Initialize</c> call.</exception>
    public static Pkcs11Library Load(string libraryPath, Pkcs11LibraryOptions? options = null)
        => new(libraryPath, logger =>
        {
            // Resolved once, here, so the warning names the file that is then loaded, even if another thread
            // changes the current directory in between.
            string path = libraryPath;
            if (!string.IsNullOrEmpty(libraryPath) && ModulePath.Classify(libraryPath) == ModulePathKind.Relative)
            {
                path = Path.GetFullPath(libraryPath);
                Log.LoadingModuleFromRelativePath(logger, libraryPath, path);
            }
            return new LowLevelPkcs11Library(path);
        }, options);

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
    /// <see cref="Load(string, Pkcs11LibraryOptions?)"/> when you mean a specific module.
    /// </para>
    /// </remarks>
    /// <param name="options">
    /// Logging and module-specific initialization settings; see <see cref="Pkcs11LibraryOptions"/>.
    /// Pass <see langword="null"/> (the default) for no logging and a standard initialization.
    /// </param>
    /// <returns>A loaded, initialized <see cref="Pkcs11Library"/> bound to the statically linked module.</returns>
    /// <exception cref="EntryPointNotFoundException">
    /// The host executable does not export <c>C_GetFunctionList</c>.
    /// </exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_Initialize</c> call.</exception>
    public static Pkcs11Library LoadStaticallyLinked(Pkcs11LibraryOptions? options = null)
        => new(libraryPath: "<statically-linked>", _ => new LowLevelPkcs11Library(), options);

    /// <summary>
    /// Test seam: binds to a module whose exports come from <paramref name="resolveExport"/> (a fake
    /// module built from managed <c>[UnmanagedCallersOnly]</c> functions), then initializes it exactly
    /// as <see cref="Load(string, Pkcs11LibraryOptions?)"/> does. Every call crosses the real loader, wrappers,
    /// pinning and struct packing.
    /// </summary>
    internal Pkcs11Library(Func<string, IntPtr> resolveExport, Pkcs11LibraryOptions? options = null)
        : this(libraryPath: "<fake module>", _ => new LowLevelPkcs11Library(resolveExport), options)
    {
    }

    private Pkcs11Library(string libraryPath, Func<ILogger, LowLevelPkcs11Library> load, Pkcs11LibraryOptions? options)
    {
        ILoggerFactory? loggerFactory = options?.LoggerFactory;
        _loggerFactory = loggerFactory;
        CurveCatalog = options?.CurveCatalog ?? Pkcs11CurveCatalog.Default;
        _logger = (loggerFactory ?? NullLoggerFactory.Instance).CreateLogger<Pkcs11Library>();
        Log.LibraryTrace(_logger, libraryPath, "ctor");

        _libraryPath = libraryPath;

        try
        {
            Log.LoadingLibrary(_logger, _libraryPath);
            _pkcs11Library = load(_logger);
            _pkcs11Library.Pbkdf2PasswordLengthByReference = options?.Pbkdf2ParametersLayout switch
            {
                Pbkdf2ParametersLayout.PasswordLengthByReference => true,
                Pbkdf2ParametersLayout.PasswordLengthByValue => false,
                _ => null,
            };
            Initialize(options);

            // After C_Initialize, so it joins the event stream of the module as now initialized.
            _slotEvents = _pkcs11Library.Module.SlotEvents.Subscribe(_pkcs11Library);
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
                    Log.OsLockingRefused(_logger, _libraryPath);
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

        CKR rv = LowLevel.C_GetInfo(out CK_INFO info);
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
    /// When <see langword="true"/> (the default), returns only slots that currently have a token
    /// inserted. When <see langword="false"/>, returns all slots regardless of token presence —
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
            list.Add(new Pkcs11Slot(this, (ulong)slot, _loggerFactory));

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
    /// <param name="interfaceName">The interface name to request (e.g. <c>"PKCS 11"</c>), or <see langword="null"/> for the module's default interface.</param>
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
    /// <see cref="WaitForSlotEvent"/> and <see cref="WaitForSlotEventAsync"/> are refused when this is <see langword="false"/>;
    /// <see cref="TryGetSlotEvent"/> still works.
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
    /// Blocks until a slot event, such as token insertion or token removal, occurs.
    /// </summary>
    /// <param name="cancellationToken">Ends the wait without an event.</param>
    /// <returns>
    /// The slot the event occurred in. It equals the slot with the same id in <see cref="GetSlotList"/>.
    /// Call <see cref="Pkcs11Slot.GetTokenInfo"/> or <see cref="Pkcs11Slot.GetSlotInfo"/> on it to learn
    /// whether a token was inserted or removed: the event itself does not say which.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The slot may be one <see cref="GetSlotList"/> has not reported before, such as a reader plugged in
    /// after the module was loaded. Many modules only add such a slot to their table when the slot list is
    /// read again, and answer <c>CKR_SLOT_ID_INVALID</c> until then: call <see cref="GetSlotList"/> before
    /// using a slot it has not reported.
    /// </para>
    /// <para>
    /// Every <see cref="Pkcs11Library"/> loaded from a module sees every slot event of that module, however
    /// many of them wait or poll: the module is waited on once, on a background thread, and each event goes
    /// to each library. Within one library, an event is taken once: by the longest-waiting
    /// <see cref="WaitForSlotEvent"/> or <see cref="WaitForSlotEventAsync"/>, or else by the next one, or by
    /// <see cref="TryGetSlotEvent"/>. Events in one slot that have not been taken yet merge into one.
    /// </para>
    /// <para>
    /// The wait ends without an event when <paramref name="cancellationToken"/> is cancelled
    /// (<see cref="OperationCanceledException"/>) or this library is disposed
    /// (<see cref="ObjectDisposedException"/>). It needs a module that may be called concurrently
    /// (<see cref="SupportsConcurrentAccess"/>): otherwise the wait would hold the module's only lock until
    /// an event came, keeping out every other call. Poll with <see cref="TryGetSlotEvent"/> there instead.
    /// Many modules do not implement a blocking wait and throw <c>CKR_FUNCTION_NOT_SUPPORTED</c>; poll
    /// <see cref="GetSlotList"/> on those.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed, before or during
    /// the wait.</exception>
    /// <exception cref="OperationCanceledException">Thrown if <paramref name="cancellationToken"/> is
    /// cancelled.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="SupportsConcurrentAccess"/> is
    /// <see langword="false"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_WaitForSlotEvent</c> call,
    /// including <c>CKR_NO_EVENT</c>, which a blocking call must not return. Every wait on the module at
    /// the time receives it.</exception>
    public Pkcs11Slot WaitForSlotEvent(CancellationToken cancellationToken = default)
        => WaitForSlotEventAsync(cancellationToken).GetAwaiter().GetResult();

    /// <summary>
    /// Waits asynchronously for a slot event, such as token insertion or token removal. See
    /// <see cref="WaitForSlotEvent"/>, which this is the asynchronous form of.
    /// </summary>
    /// <param name="cancellationToken">Ends the wait without an event.</param>
    /// <returns>The slot the event occurred in.</returns>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed, before or during
    /// the wait.</exception>
    /// <exception cref="OperationCanceledException">Thrown if <paramref name="cancellationToken"/> is
    /// cancelled.</exception>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="SupportsConcurrentAccess"/> is
    /// <see langword="false"/>.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_WaitForSlotEvent</c> call.</exception>
    public Task<Pkcs11Slot> WaitForSlotEventAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!SupportsConcurrentAccess)
            throw new InvalidOperationException(
                "A blocking WaitForSlotEvent needs a module that may be called concurrently, and this one may not " +
                "(see SupportsConcurrentAccess). Poll with TryGetSlotEvent instead.");

        Log.LibraryTrace(_logger, _libraryPath, "WaitForSlotEvent");
        _ = LowLevel;
        return Core(SlotEvents.WaitAsync(cancellationToken));

        async Task<Pkcs11Slot> Core(Task<ulong> wait)
            => new(this, await wait.ConfigureAwait(false), _loggerFactory);
    }

    /// <summary>
    /// Reports a pending slot event, such as token insertion or token removal, without waiting for one.
    /// </summary>
    /// <param name="slot">
    /// The slot the event occurred in, when one was pending; otherwise <see langword="null"/>. It equals the
    /// slot with the same id in <see cref="GetSlotList"/>. Call <see cref="Pkcs11Slot.GetTokenInfo"/> or
    /// <see cref="Pkcs11Slot.GetSlotInfo"/> on it to learn whether a token was inserted or removed: the
    /// event itself does not say which. As with <see cref="WaitForSlotEvent"/>, call
    /// <see cref="GetSlotList"/> before using a slot it has not reported.
    /// </param>
    /// <returns><see langword="true"/> if an event was pending; <see langword="false"/> if none was.</returns>
    /// <remarks>
    /// <para>
    /// While a <see cref="WaitForSlotEvent"/> runs on any library loaded from the module, this only takes
    /// what that wait has already received for this library. Otherwise it asks the module, with
    /// <c>CKF_DONT_BLOCK</c>; polls from several threads and libraries take turns.
    /// </para>
    /// <para>
    /// Works on a module that may not be called concurrently, provided the module honors
    /// <c>CKF_DONT_BLOCK</c>. Some do not, and block anyway: on such a module, when it may not be called
    /// concurrently, the poll holds the module's only lock until an event comes, and keeps every other call
    /// out until then. Many modules do not implement <c>C_WaitForSlotEvent</c> at all and throw
    /// <c>CKR_FUNCTION_NOT_SUPPORTED</c>; poll <see cref="GetSlotList"/> on those.
    /// </para>
    /// </remarks>
    /// <exception cref="ObjectDisposedException">Thrown if the library has been disposed.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying <c>C_WaitForSlotEvent</c> call.</exception>
    public bool TryGetSlotEvent([NotNullWhen(true)] out Pkcs11Slot? slot)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "TryGetSlotEvent");
        _ = LowLevel;
        if (!SlotEvents.TryTake(out ulong slotId))
        {
            slot = null;
            return false;
        }
        slot = new Pkcs11Slot(this, slotId, _loggerFactory);
        return true;
    }

    private SlotEventSubscription SlotEvents => _slotEvents ?? throw new ObjectDisposedException(nameof(Pkcs11Library));

    /// <summary>
    /// Finds the one slot whose token's label is <paramref name="tokenLabel"/>, among the slots with a token
    /// present. The comparison is ordinal (case-sensitive), after removing the trailing spaces PKCS#11 pads a
    /// label with. Finding the slot neither opens a session nor logs in.
    /// </summary>
    /// <remarks>
    /// PKCS#11 does not make labels unique: two tokens may share one (a cloned card, two HSM partitions given the same
    /// name). When more than one does, this refuses rather than picking one, which would let whoever can initialize a
    /// token decide which one the application uses: select the token by its serial number
    /// (<see cref="GetSlotByTokenSerial"/>), a PKCS#11 URI (<see cref="GetSlotByUri(string)"/>) or a predicate
    /// (<see cref="GetSlot"/>) instead. A slot ID is no substitute: the module assigns it, and it can change between
    /// runs or name another token after a card is swapped. A token removed while the slots are being read is passed
    /// over.
    /// </remarks>
    /// <param name="tokenLabel">The token label, without its padding.</param>
    /// <returns>The slot holding the token.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tokenLabel"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">The library has been disposed.</exception>
    /// <exception cref="Pkcs11TokenException">No present token has the label (<see cref="CKR.CKR_TOKEN_NOT_PRESENT"/>).</exception>
    /// <exception cref="Pkcs11AmbiguousTokenException">More than one present token has the label; it names their slots.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetSlotList</c> or <c>C_GetTokenInfo</c>.</exception>
    public Pkcs11Slot GetSlotByTokenLabel(string tokenLabel)
    {
        ArgumentNullException.ThrowIfNull(tokenLabel);
        ObjectDisposedException.ThrowIf(_disposed, this);

        return SelectOneSlot((_, token) => string.Equals(token.Label.TrimEnd(' '), tokenLabel, StringComparison.Ordinal),
            $"the label '{tokenLabel}'");
    }

    /// <summary>
    /// Finds the one slot whose token's serial number (<c>CK_TOKEN_INFO.serialNumber</c>) is
    /// <paramref name="serialNumber"/>, among the slots with a token present: the way to tell apart tokens that share a
    /// label. The comparison is ordinal (case-sensitive), after removing the padding. Finding the slot neither opens a
    /// session nor logs in.
    /// </summary>
    /// <remarks>
    /// A serial number is unique for a manufacturer and model, not across them: two tokens of different makes may report
    /// the same one, and this then refuses rather than picking one. Add the manufacturer or model with
    /// <see cref="GetSlotByUri(string)"/> (<c>pkcs11:manufacturer=…;serial=…</c>) or <see cref="GetSlot"/>.
    /// </remarks>
    /// <param name="serialNumber">The token's serial number, without its padding.</param>
    /// <returns>The slot holding the token.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="serialNumber"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">The library has been disposed.</exception>
    /// <exception cref="Pkcs11TokenException">No present token has the serial number (<see cref="CKR.CKR_TOKEN_NOT_PRESENT"/>).</exception>
    /// <exception cref="Pkcs11AmbiguousTokenException">More than one present token has it; it names their slots.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetSlotList</c> or <c>C_GetTokenInfo</c>.</exception>
    public Pkcs11Slot GetSlotByTokenSerial(string serialNumber)
    {
        ArgumentNullException.ThrowIfNull(serialNumber);
        ObjectDisposedException.ThrowIf(_disposed, this);

        return SelectOneSlot(
            (_, token) => string.Equals(token.SerialNumber.TrimEnd(' '), serialNumber, StringComparison.Ordinal),
            $"the serial number '{serialNumber}'");
    }

    /// <summary>
    /// Finds the one slot whose token <paramref name="match"/> accepts, among the slots with a token present: for a
    /// selection the other lookups do not express (a label and a model, a manufacturer prefix, a flag). Finding the slot
    /// neither opens a session nor logs in.
    /// </summary>
    /// <remarks>
    /// <paramref name="match"/> sees each present token's <see cref="TokenInfo"/> (its text fields without their
    /// padding, and its <see cref="TokenInfo.SlotId"/>), and must accept exactly one: none, or more than one, is
    /// refused rather than resolved by picking one. A token removed while the slots are being read is passed over.
    /// </remarks>
    /// <param name="match">Whether a token is the one wanted. An exception it throws propagates.</param>
    /// <returns>The slot holding the token.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="match"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">The library has been disposed.</exception>
    /// <exception cref="Pkcs11TokenException">No present token matches (<see cref="CKR.CKR_TOKEN_NOT_PRESENT"/>).</exception>
    /// <exception cref="Pkcs11AmbiguousTokenException">More than one present token matches; it names their slots.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetSlotList</c> or <c>C_GetTokenInfo</c>.</exception>
    public Pkcs11Slot GetSlot(Func<TokenInfo, bool> match)
    {
        ArgumentNullException.ThrowIfNull(match);
        ObjectDisposedException.ThrowIf(_disposed, this);

        return SelectOneSlot((_, token) => match(token), "the properties asked for");
    }

    /// <summary>
    /// Finds the one slot holding the token a PKCS#11 URI (RFC 7512) names, among the slots with a token present: for
    /// instance <c>pkcs11:token=signing-prod;serial=0123456789abcdef</c>, or
    /// <c>pkcs11:manufacturer=SoftHSM%20project;model=SoftHSM%20v2;token=signing-prod</c>. Finding the slot neither
    /// opens a session nor logs in. See <see cref="GetSlotByUri(Pkcs11Uri)"/>.
    /// </summary>
    /// <param name="uri">The URI; see <see cref="Pkcs11Uri"/> for what is taken and what is refused.</param>
    /// <returns>The slot holding the token.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="uri"/> is not a PKCS#11 URI this library takes (see <see cref="Pkcs11Uri"/>).</exception>
    /// <exception cref="ObjectDisposedException">The library has been disposed.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// No present token matches, or the module is not the one the <c>library-*</c> attributes name
    /// (<see cref="CKR.CKR_TOKEN_NOT_PRESENT"/>).
    /// </exception>
    /// <exception cref="Pkcs11AmbiguousTokenException">More than one present token matches; it names their slots.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetInfo</c>, <c>C_GetSlotList</c>, <c>C_GetSlotInfo</c> or <c>C_GetTokenInfo</c>.</exception>
    public Pkcs11Slot GetSlotByUri(string uri) => GetSlotByUri(Pkcs11Uri.Parse(uri));

    /// <summary>
    /// Finds the one slot holding the token <paramref name="uri"/> names, among the slots with a token present. Finding
    /// the slot neither opens a session nor logs in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The module (<c>library-*</c>, checked against <see cref="GetInfo"/>), the slot (<c>slot-*</c>) and the token
    /// (<c>token</c>, <c>manufacturer</c>, <c>serial</c>, <c>model</c>) attributes select; an attribute left out matches
    /// anything, so <c>pkcs11:</c> alone names every token. The object attributes (<c>object</c>, <c>type</c>,
    /// <c>id</c>) do not take part: a key's URI selects the token it is on, and
    /// <see cref="Pkcs11Session.OpenKey(Pkcs11Uri)"/> then opens the key.
    /// </para>
    /// <para>
    /// As with the other lookups, the URI must name exactly one present token: none, or more than one, is refused rather
    /// than resolved by picking one. A <c>slot-id</c> pins the slot, which the module may renumber between runs; prefer
    /// the token's own attributes (<see cref="Pkcs11Slot.GetTokenUri"/>) in configuration.
    /// </para>
    /// </remarks>
    /// <param name="uri">The URI.</param>
    /// <returns>The slot holding the token.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException">The library has been disposed.</exception>
    /// <exception cref="Pkcs11TokenException">
    /// No present token matches, or the module is not the one the <c>library-*</c> attributes name
    /// (<see cref="CKR.CKR_TOKEN_NOT_PRESENT"/>).
    /// </exception>
    /// <exception cref="Pkcs11AmbiguousTokenException">More than one present token matches; it names their slots.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from <c>C_GetInfo</c>, <c>C_GetSlotList</c>, <c>C_GetSlotInfo</c> or <c>C_GetTokenInfo</c>.</exception>
    public Pkcs11Slot GetSlotByUri(Pkcs11Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (uri.NamesLibrary && !uri.Matches(GetInfo()))
        {
            throw new Pkcs11TokenException(CKR.CKR_TOKEN_NOT_PRESENT, Pkcs11Operations.OpGetInfo,
                "No present token matches the PKCS#11 URI: its library-* attributes do not describe this module.");
        }

        return SelectOneSlot(uri.Matches, "the attributes of the PKCS#11 URI");
    }

    // The one present token match accepts. A token removed while the slots are read is passed over. None is
    // CKR_TOKEN_NOT_PRESENT; more than one is refused, naming the slots, rather than resolved by picking one.
    private Pkcs11Slot SelectOneSlot(Func<Pkcs11Slot, TokenInfo, bool> match, string what)
    {
        List<(Pkcs11Slot Slot, TokenInfo Token)> matches = [];
        foreach (Pkcs11Slot slot in GetSlotList())
        {
            TokenInfo token;
            try
            {
                token = slot.GetTokenInfo();
                if (!match(slot, token))
                    continue;
            }
            catch (Pkcs11TokenException ex) when (ex.ReturnValue is CKR.CKR_TOKEN_NOT_PRESENT or CKR.CKR_DEVICE_REMOVED)
            {
                continue;
            }

            matches.Add((slot, token));
        }

        // The slot remembers the token it was selected by: a login through it checks the slot still holds that token
        // before sending the PIN.
        return matches.Count switch
        {
            1 => matches[0].Slot.SelectedBy(matches[0].Token),
            0 => throw new Pkcs11TokenException(
                CKR.CKR_TOKEN_NOT_PRESENT,
                Pkcs11Operations.OpGetTokenInfo,
                $"No present token has {what}."),
            _ => throw new Pkcs11AmbiguousTokenException(
                Pkcs11Operations.OpGetTokenInfo,
                $"More than one token has {what}: slots {string.Join(", ", matches.Select(m => m.Slot.SlotId))}. "
                + "Select the token by what tells them apart: its serial number (GetSlotByTokenSerial), a PKCS#11 URI "
                + "with its manufacturer or model (GetSlotByUri), or a predicate (GetSlot).",
                [.. matches.Select(m => m.Slot.SlotId)]),
        };
    }

    #region IDisposable

    /// <summary>
    /// Releases the library: closes any sessions still tracked against it, and releases the module.
    /// <c>C_Finalize</c> (only if this instance drove <c>C_Initialize</c>) and the unmap run when the
    /// last use of the module goes: at once, or when a call still in flight on another thread returns.
    /// A thread waiting in <see cref="WaitForSlotEvent"/> or <see cref="WaitForSlotEventAsync"/> on this
    /// library gets <see cref="ObjectDisposedException"/> at once. While another load of the same module
    /// still needs it, <c>C_Finalize</c> waits for that one too, since they share the module's state; a
    /// blocking <c>C_WaitForSlotEvent</c> still inside the module does not delay it, and is woken by it, as
    /// PKCS#11 specifies. It therefore runs on whichever thread releases the last use. Dispose logs what it
    /// can know of it: a failure when it ran at once, or that it was deferred or left to another load.
    /// There is no finalizer — the native module is released by <c>Pkcs11ModuleHandle</c>'s
    /// critical-finalizer <see cref="SafeHandle"/> if a caller forgets to dispose.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        Volatile.Write(ref _disposing, 1);
        Log.LibraryTrace(_logger, _libraryPath, "Dispose");

        // First: ends this library's slot-event waits at once, whatever else still uses the module.
        _slotEvents?.Dispose();
        _slotEvents = null;

        if (_pkcs11Library != null)
        {
            // This library's holds of token logins (its Pkcs11Login objects and their sessions) are released
            // first: a login it alone held is logged out, while its anchor is still there to send C_Logout on (or, with
            // operations in flight on the token, as the last of them ends; the anchor holds off C_Finalize until then).
            // A login another load of the module still holds stays, with its anchor (see CloseAllTrackedSessions),
            // which holds off this load's C_Finalize until that login's last holder goes.
            // Every record is released, and the rest of the disposal runs, even when one release throws (a logger's
            // exception, say): that exception is reported once the library is disposed.
            try
            {
                ReleaseHoldersFrom(TokenLoginRegistry.Of(_pkcs11Library.Module).Records(), 0);
            }
            finally
            {
                CloseAndRelease();
            }
        }

        _disposed = true;
    }

    // Releases this library's holds in records[index..], each even if the one before it threw.
    private void ReleaseHoldersFrom(TokenLoginRecord[] records, int index)
    {
        if (index == records.Length)
            return;
        try
        {
            records[index].ReleaseHoldersOf(this);
        }
        finally
        {
            ReleaseHoldersFrom(records, index + 1);
        }
    }

    // The end of Dispose, once the login holds are released.
    private void CloseAndRelease()
    {
        if (_pkcs11Library is null)
            return;
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
