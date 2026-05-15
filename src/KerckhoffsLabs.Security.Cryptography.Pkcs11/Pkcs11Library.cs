using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// High level PKCS#11 wrapper
/// </summary>
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
    private string? _libraryPath = null;

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    private LowLevelPkcs11Library? _pkcs11Library = null;

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
        => new Pkcs11Library(libraryPath: "<statically-linked>", useStaticLink: true);

    private Pkcs11Library(string libraryPath, bool useStaticLink)
    {
        _logger.LogDebug("Pkcs11Library({LibraryPath})::ctor", libraryPath);

        _libraryPath = libraryPath;

        try
        {
            _logger.LogInformation("Loading PKCS#11 library {LibraryPath}", _libraryPath);
            _pkcs11Library = useStaticLink
                ? new LowLevelPkcs11Library()
                : new LowLevelPkcs11Library(_libraryPath);
            Initialize();
        }
        catch
        {
            if (_pkcs11Library != null)
            {
                _logger.LogInformation("Unloading PKCS#11 library {LibraryPath}", _libraryPath);
                _pkcs11Library.Dispose();
                _pkcs11Library = null;
            }

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
        _logger.LogDebug("Pkcs11Library({LibraryPath})::Initialize", _libraryPath);

        var initArgs = new CK_C_INITIALIZE_ARGS { Flags = CKF.CKF_OS_LOCKING_OK };
        CKR rv = _pkcs11Library.C_Initialize(initArgs);

        // Another component already initialized the library — treat as success.
        if (rv == CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED) return;

        // Token refused OS locking. Retry without — application is single-threaded
        // from the library's perspective; caller must serialize at the C# layer.
        if (rv == CKR.CKR_CANT_LOCK)
        {
            _logger.LogWarning(
                "PKCS#11 library {LibraryPath} refused CKF_OS_LOCKING_OK; retrying without OS locking",
                _libraryPath);
            rv = _pkcs11Library.C_Initialize(null);
            if (rv == CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED) return;
        }

        Pkcs11Exception.ThrowIfError(rv, "C_Initialize");
    }

    /// <summary>
    /// Gets general information about loaded PKCS#11 library
    /// </summary>
    /// <returns>General information about loaded PKCS#11 library</returns>
    public LibraryInfo GetInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.LogDebug("Pkcs11Library({LibraryPath})::GetInfo", _libraryPath);

        CK_INFO info = new();
        CKR rv = _pkcs11Library.C_GetInfo(ref info);
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
    /// <returns>List of available slots.</returns>
    public List<Pkcs11Slot> GetSlotList(bool tokenPresent = true)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.LogDebug("Pkcs11Library({LibraryPath})::GetSlotList", _libraryPath);

        NativeCULong slotCount = new(0);
        CKR rv = _pkcs11Library.C_GetSlotList(tokenPresent, null, ref slotCount);
        Pkcs11Exception.ThrowIfError(rv, "C_GetSlotList");

        if (slotCount.Value == 0)
        {
            return [];
        }
        else
        {
            NativeCULong[] slotList = new NativeCULong[slotCount.Value];
            rv = _pkcs11Library.C_GetSlotList(tokenPresent, slotList, ref slotCount);
            Pkcs11Exception.ThrowIfError(rv, "C_GetSlotList");

            if (new NativeCULong((uint)slotList.Length).Value != slotCount.Value)
                Array.Resize(ref slotList, (int)(slotCount));

            List<Pkcs11Slot> list = [];
            foreach (NativeCULong slot in slotList)
                list.Add(new Pkcs11Slot(_pkcs11Library, (ulong)slot));

            return list;
        }
    }

    /// <summary>
    /// Waits for a slot event, such as token insertion or token removal, to occur.
    /// </summary>
    /// <param name="nonBlocking">
    /// When <c>true</c>, returns immediately even if no event is pending
    /// (<paramref name="eventOccured"/> will be <c>false</c>). When <c>false</c>,
    /// blocks until an event occurs.
    /// </param>
    /// <param name="eventOccured">True when a slot event was reported.</param>
    /// <param name="slotId">PKCS#11 handle of the slot the event occurred in. Zero when no event.</param>
    public void WaitForSlotEvent(bool nonBlocking, out bool eventOccured, out ulong slotId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.LogDebug("Pkcs11Library({LibraryPath})::WaitForSlotEvent", _libraryPath);

        NativeCULong flags = nonBlocking ? CKF.CKF_DONT_BLOCK : new(0);
        NativeCULong slotIdOut = new(0);
        CKR rv = _pkcs11Library.C_WaitForSlotEvent(flags, ref slotIdOut, IntPtr.Zero);

        if (rv == CKR.CKR_OK)
        {
            eventOccured = true;
            slotId = (ulong)slotIdOut;
            return;
        }

        eventOccured = false;
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
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        _logger.LogDebug("Pkcs11Library({LibraryPath})::Dispose1", _libraryPath);

        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    private void Dispose(bool disposing)
    {
        _logger.LogDebug("Pkcs11Library({LibraryPath})::Dispose2", _libraryPath);

        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed objects
                if (_pkcs11Library != null)
                {
                    _pkcs11Library.C_Finalize(IntPtr.Zero);

                    _logger.LogInformation("Unloading PKCS#11 library {LibraryPath}", _libraryPath);
                    _pkcs11Library.Dispose();
                    _pkcs11Library = null;
                }
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~Pkcs11Library()
    {
        Dispose(false);
    }

    #endregion
}