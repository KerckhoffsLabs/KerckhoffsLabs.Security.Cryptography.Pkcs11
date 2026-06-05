using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

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
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    private bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger<Pkcs11Library>();

    /// <summary>
    /// Library name or path
    /// </summary>
    private readonly string? _libraryPath = null;

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    private ILowLevelPkcs11Library? _pkcs11Library = null;

    /// <summary>
    /// The loaded low-level library. Set during construction and released on
    /// <see cref="Dispose()"/>; accessing it afterwards throws.
    /// </summary>
    private ILowLevelPkcs11Library LowLevel => _pkcs11Library
        ?? throw new ObjectDisposedException(nameof(Pkcs11Library));

    /// <summary>
    /// True only when <see cref="Initialize"/> drove <c>C_Initialize</c> to <c>CKR_OK</c>.
    /// Stays false when another <see cref="Pkcs11Library"/> instance (or a different
    /// component in the same process) had already initialized the library and we observed
    /// <c>CKR_CRYPTOKI_ALREADY_INITIALIZED</c>. <see cref="Dispose()"/> gates
    /// <c>C_Finalize</c> on this flag so we never tear down another owner's state.
    /// </summary>
    private bool _weInitialized = false;

    /// <summary>
    /// Test seam: access to the underlying low-level wrapper for regression checks on
    /// session tracking. Not exposed publicly.
    /// </summary>
    internal ILowLevelPkcs11Library? LowLevelLibrary => _pkcs11Library;

    /// <summary>
    /// Loads and initializes the PKCS#11 library at <paramref name="libraryPath"/>.
    /// Function pointers are acquired via <c>C_GetFunctionList</c> (the PKCS#11
    /// v2.20+ recommended path).
    /// </summary>
    /// <param name="libraryPath">Library name or path.</param>
    public Pkcs11Library(string libraryPath)
        : this(libraryPath, useStaticLink: false) { }

    /// <summary>
    /// Binds to a PKCS#11 implementation that is statically linked into the host
    /// executable, rather than dynamically loaded from a path. Use this entry
    /// point on platforms where dynamic library loading is unavailable or
    /// restricted (iOS, Native AOT, single-file embedded builds).
    /// </summary>
    /// <remarks>
    /// The host must export the cryptoki <c>C_GetFunctionList</c> symbol at link
    /// time via <c>DllImport("__Internal")</c>. All subsequent PKCS#11 calls go
    /// through the function-pointer table returned by that single call — no
    /// other unmanaged bindings are required.
    /// </remarks>
    public static Pkcs11Library LoadStaticallyLinked()
        => new(libraryPath: "<statically-linked>", useStaticLink: true);

    private Pkcs11Library(string libraryPath, bool useStaticLink)
    {
        Log.LibraryTrace(_logger, libraryPath, "ctor");

        _libraryPath = libraryPath;

        try
        {
            Log.LoadingLibrary(_logger, _libraryPath);
            _pkcs11Library = useStaticLink
                ? new LowLevelPkcs11Library()
                : new LowLevelPkcs11Library(_libraryPath);
            Initialize();
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
    /// Test seam: binds to an in-process <see cref="ILowLevelPkcs11Library"/> implementation
    /// (e.g. a managed fake token) instead of a dynamically loaded native module, then drives
    /// <c>C_Initialize</c> exactly as the production ctor does. Lets the high-level API and the
    /// <c>Algorithms</c> adapters be exercised end-to-end without a native PKCS#11 library.
    /// </summary>
    internal Pkcs11Library(ILowLevelPkcs11Library lowLevel)
    {
        ArgumentNullException.ThrowIfNull(lowLevel);
        _libraryPath = "<in-process>";
        _pkcs11Library = lowLevel;

        try
        {
            Initialize();
        }
        catch
        {
            lowLevel.Dispose();
            _pkcs11Library = null;
            throw;
        }
    }

    /// <summary>
    /// Initializes the PKCS#11 library. Probes with <c>CKF_OS_LOCKING_OK</c>
    /// first (the safe default for multi-threaded callers); falls back to a
    /// null-args call if the token returns <c>CKR_CANT_LOCK</c>.
    /// </summary>
    /// <remarks>
    /// Per PKCS#11 v3.1 §5.4, a token may refuse <c>CKF_OS_LOCKING_OK</c>; the
    /// spec calls out <c>CKR_CANT_LOCK</c> as the expected return code in that
    /// case. The fallback path uses <c>pInitArgs = NULL</c>, which declares the
    /// application will not access the library from multiple threads
    /// concurrently — callers in that mode are responsible for serializing
    /// access at the C# level.
    /// </remarks>
    private void Initialize()
    {
        Log.LibraryTrace(_logger, _libraryPath, "Initialize");

        var initArgs = new CK_C_INITIALIZE_ARGS { Flags = CKF.CKF_OS_LOCKING_OK };
        CKR rv = LowLevel.C_Initialize(initArgs);

        // Another component already initialized the library — treat as success but
        // leave _weInitialized = false so Dispose doesn't tear down their state.
        if (rv == CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED) return;

        // Token refused OS locking. Retry without — application is single-threaded
        // from the library's perspective; caller must serialize at the C# layer.
        if (rv == CKR.CKR_CANT_LOCK)
        {
            _logger.LogWarning(
                "PKCS#11 library {LibraryPath} refused CKF_OS_LOCKING_OK; retrying without OS locking",
                _libraryPath);
            rv = LowLevel.C_Initialize(null);
            if (rv == CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED) return;
        }

        Pkcs11Exception.ThrowIfError(rv, "C_Initialize");
        _weInitialized = true;
    }

    /// <summary>
    /// Gets general information about loaded PKCS#11 library
    /// </summary>
    /// <returns>General information about loaded PKCS#11 library</returns>
    public LibraryInfo GetInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "GetInfo");

        CK_INFO info = new();
        CKR rv = LowLevel.C_GetInfo(ref info);
        Pkcs11Exception.ThrowIfError(rv, "C_GetInfo");

        return new LibraryInfo(info);
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
    public IReadOnlyList<Pkcs11Slot> GetSlotList(bool tokenPresent = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "GetSlotList");

        NativeCULong slotCount = new(0);
        CKR rv = LowLevel.C_GetSlotList(tokenPresent, null, ref slotCount);
        Pkcs11Exception.ThrowIfError(rv, "C_GetSlotList");

        if (slotCount.Value == 0)
        {
            return [];
        }
        else
        {
            NativeCULong[] slotList = new NativeCULong[slotCount.Value];
            rv = LowLevel.C_GetSlotList(tokenPresent, slotList, ref slotCount);
            Pkcs11Exception.ThrowIfError(rv, "C_GetSlotList");

            // The token may report a different count on the second call; resize to match.
            if (slotList.Length != (int)slotCount)
                Array.Resize(ref slotList, (int)slotCount);

            List<Pkcs11Slot> list = [];
            foreach (NativeCULong slot in slotList)
                list.Add(new Pkcs11Slot(LowLevel, (ulong)slot));

            return list;
        }
    }

    /// <summary>
    /// Enumerates the interfaces this module exposes (PKCS#11 v3.0 <c>C_GetInterfaceList</c>) —
    /// the standard <c>"PKCS 11"</c> interface plus any vendor-specific ones. This is the only way
    /// to discover vendor interface tables a token offers.
    /// </summary>
    /// <returns>The interface descriptors, or an empty list if the module reports none.</returns>
    /// <exception cref="Exceptions.Pkcs11Exception">
    /// Thrown with <see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 modules, which have no
    /// interface concept.
    /// </exception>
    public IReadOnlyList<InterfaceInfo> GetInterfaces()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "GetInterfaces");

        NativeCULong count = new(0);
        CKR rv = LowLevel.C_GetInterfaceList(null, ref count);
        Pkcs11Exception.ThrowIfError(rv, "C_GetInterfaceList");

        if (count.Value == 0)
            return [];

        CK_INTERFACE[] raw = new CK_INTERFACE[(int)count];
        rv = LowLevel.C_GetInterfaceList(raw, ref count);
        Pkcs11Exception.ThrowIfError(rv, "C_GetInterfaceList");

        // The module may report fewer on the second call; never read past the buffer.
        int n = Math.Min((int)count, raw.Length);
        List<InterfaceInfo> list = new(n);
        for (int i = 0; i < n; i++)
        {
            string name = raw[i].InterfaceName != IntPtr.Zero
                ? Marshal.PtrToStringUTF8(raw[i].InterfaceName) ?? string.Empty
                : string.Empty;
            list.Add(new InterfaceInfo(name, raw[i].Flags));
        }

        return list;
    }

    /// <summary>
    /// Waits for a slot event, such as token insertion or token removal, to occur.
    /// </summary>
    /// <param name="nonBlocking">
    /// When <c>true</c>, returns immediately even if no event is pending
    /// (<paramref name="eventOccurred"/> will be <c>false</c>). When <c>false</c>,
    /// blocks until an event occurs.
    /// </param>
    /// <param name="eventOccurred">True when a slot event was reported.</param>
    /// <param name="slotId">PKCS#11 handle of the slot the event occurred in. Zero when no event.</param>
    public void WaitForSlotEvent(bool nonBlocking, out bool eventOccurred, out ulong slotId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Log.LibraryTrace(_logger, _libraryPath, "WaitForSlotEvent");

        NativeCULong flags = nonBlocking ? CKF.CKF_DONT_BLOCK : new(0);
        NativeCULong slotIdOut = new(0);
        CKR rv = LowLevel.C_WaitForSlotEvent(flags, ref slotIdOut, IntPtr.Zero);

        if (rv == CKR.CKR_OK)
        {
            eventOccurred = true;
            slotId = (ulong)slotIdOut;
            return;
        }

        eventOccurred = false;
        slotId = 0;

        // CKR_NO_EVENT is expected in non-blocking mode when nothing's pending.
        if (nonBlocking && rv == CKR.CKR_NO_EVENT) return;

        Pkcs11Exception.ThrowIfError(rv, "C_WaitForSlotEvent");
    }

    /// <summary>
    /// Opens an authenticated workspace against the slot whose token label matches
    /// <paramref name="slotLabel"/>.
    /// </summary>
    /// <param name="slotLabel">The token label (case-sensitive, trimmed of trailing
    /// spaces — PKCS#11 pads labels with spaces to 32 chars).</param>
    /// <param name="userType">The PKCS#11 user type to log in as.</param>
    /// <param name="pin">The PIN. The workspace does not retain the PIN past construction.</param>
    /// <returns>An open <see cref="Pkcs11Workspace"/>. Callers must <c>Dispose</c> it.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="slotLabel"/> or <paramref name="pin"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if no slot with a matching token label is present.</exception>
    /// <exception cref="Pkcs11Exception">Propagated from the underlying PKCS#11 calls.</exception>
    public Pkcs11Workspace OpenWorkspace(string slotLabel, CKU userType, SecurePin pin)
    {
        ArgumentNullException.ThrowIfNull(slotLabel);
        ArgumentNullException.ThrowIfNull(pin);

        Pkcs11Slot? matched = null;
        foreach (var slot in GetSlotList())
        {
            if (slot.GetTokenInfo().Label.TrimEnd() == slotLabel)
            {
                matched = slot;
                break;
            }
        }

        if (matched is null)
            throw new ArgumentException(
                $"No slot found with token label '{slotLabel}'.", nameof(slotLabel));

        var session = matched.OpenSession();
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

    #region IDisposable

    /// <summary>
    /// Releases the library: closes any sessions still tracked against it, calls
    /// <c>C_Finalize</c> (only if this instance drove <c>C_Initialize</c>), and disposes the
    /// underlying low-level wrapper. There is no finalizer — the native module is released by
    /// <c>Pkcs11ModuleHandle</c>'s critical-finalizer <see cref="System.Runtime.InteropServices.SafeHandle"/>
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
            _pkcs11Library.CloseAllTrackedSessions();

            // Only call C_Finalize if THIS instance drove the C_Initialize to CKR_OK.
            // If we observed CKR_CRYPTOKI_ALREADY_INITIALIZED, another owner is
            // responsible for finalization — calling it here would tear down their state.
            if (_weInitialized)
                _pkcs11Library.C_Finalize(IntPtr.Zero);

            Log.UnloadingLibrary(_logger, _libraryPath);
            _pkcs11Library.Dispose();
            _pkcs11Library = null;
        }

        _disposed = true;
    }

    #endregion
}
