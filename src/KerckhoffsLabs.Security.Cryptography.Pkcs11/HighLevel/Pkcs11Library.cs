using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// High level PKCS#11 wrapper
/// </summary>
public class Pkcs11Library : IDisposable
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    protected bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private static readonly ILogger _logger = Pkcs11Logging.CreateLogger<Pkcs11Library>();

    /// <summary>
    /// Library name or path
    /// </summary>
    protected string? _libraryPath = null;

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    protected LowLevelPkcs11Library? _pkcs11Library = null;

    /// <summary>
    /// Initializes new instance of Pkcs11Library class
    /// </summary>
    /// <param name="libraryPath">Library name or path</param>
    public Pkcs11Library(string libraryPath) : this(libraryPath, AppType.SingleThreaded, InitType.WithFunctionList) { }

    /// <summary>
    /// Loads and initializes PCKS#11 library
    /// </summary>
    /// <param name="libraryPath">Library name or path</param>
    /// <param name="appType">Type of application that will be using PKCS#11 library</param>
    public Pkcs11Library(string libraryPath, AppType appType) : this(libraryPath, appType, InitType.WithFunctionList) { }

    /// <summary>
    /// Loads and initializes PCKS#11 library
    /// </summary>
    /// <param name="libraryPath">Library name or path</param>
    /// <param name="appType">Type of application that will be using PKCS#11 library</param>
    /// <param name="initType">Source of PKCS#11 function pointers</param>
    public Pkcs11Library(string libraryPath, AppType appType, InitType initType)
    {
        _logger.LogDebug("Pkcs11Library({LibraryPath})::ctor", libraryPath);

        _libraryPath = libraryPath;

        try
        {
            _logger.LogInformation("Loading PKCS#11 library {LibraryPath}", _libraryPath);
            _pkcs11Library = new LowLevelPkcs11Library(_libraryPath, initType == InitType.WithFunctionList);
            Initialize(appType);
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
    /// Initializes PCKS#11 library
    /// </summary>
    /// <param name="appType">Type of application that will be using PKCS#11 library</param>
    protected void Initialize(AppType appType)
    {
        _logger.LogDebug("Pkcs11Library({LibraryPath})::Initialize", _libraryPath);

        CK_C_INITIALIZE_ARGS initArgs = null;
        if (appType == AppType.MultiThreaded)
        {
            initArgs = new CK_C_INITIALIZE_ARGS
            {
                Flags = CKF.CKF_OS_LOCKING_OK
            };
        }

        CKR rv = _pkcs11Library.C_Initialize(initArgs);
        // CKR_CRYPTOKI_ALREADY_INITIALIZED is acceptable — another component may have
        // initialized the library before us. Treat as success.
        if (rv == CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED) return;
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
    /// Obtains a list of slots in the system
    /// </summary>
    /// <param name="slotsType">Type of slots to be obtained</param>
    /// <returns>List of available slots</returns>
    public List<Slot> GetSlotList(SlotsType slotsType)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.LogDebug("Pkcs11Library({LibraryPath})::GetSlotList", _libraryPath);

        NativeCULong slotCount = new (0);
        CKR rv = _pkcs11Library.C_GetSlotList(slotsType == SlotsType.WithTokenPresent, null, ref slotCount);
        Pkcs11Exception.ThrowIfError(rv, "C_GetSlotList");

        if (slotCount.Value == 0)
        {
            return [];
        }
        else
        {
            NativeCULong[] slotList = new NativeCULong[slotCount.Value];
            rv = _pkcs11Library.C_GetSlotList(slotsType == SlotsType.WithTokenPresent, slotList, ref slotCount);
            Pkcs11Exception.ThrowIfError(rv, "C_GetSlotList");

            if (new NativeCULong((uint)slotList.Length).Value != slotCount.Value)
                Array.Resize(ref slotList, (int)(slotCount));

            List<Slot> list = [];
            foreach (NativeCULong slot in slotList)
                list.Add(new Slot(_pkcs11Library, (ulong)slot));

            return list;
        }
    }

    /// <summary>
    /// Waits for a slot event, such as token insertion or token removal, to occur
    /// </summary>
    /// <param name="waitType">Type of waiting for a slot event</param>
    /// <param name="eventOccured">Flag indicating whether event occured</param>
    /// <param name="slotId">PKCS#11 handle of slot that the event occurred in</param>
    public void WaitForSlotEvent(WaitType waitType, out bool eventOccured, out ulong slotId)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.LogDebug("Pkcs11Library({LibraryPath})::WaitForSlotEvent", _libraryPath);

        NativeCULong flags = (waitType == WaitType.NonBlocking) ? CKF.CKF_DONT_BLOCK : new (0);

        NativeCULong slotId_ = new (0);
        CKR rv = _pkcs11Library.C_WaitForSlotEvent(flags, ref slotId_, IntPtr.Zero);
        // Initialise out params so the compiler can see definite assignment on all code paths.
        // The real values are set (or an exception is thrown) in the branches below.
        eventOccured = false;
        slotId = (ulong)slotId_;
        if (waitType == WaitType.NonBlocking)
        {
            if (rv == CKR.CKR_OK)
            {
                eventOccured = true;
                slotId = (ulong)slotId_;
            }
            else if (rv == CKR.CKR_NO_EVENT)
            {
                // No event reported. The pre-assigned defaults (eventOccured = false,
                // slotId = the native out value) already convey this — no further work needed.
            }
            else
            {
                Pkcs11Exception.ThrowIfError(rv, "C_WaitForSlotEvent");
            }
        }
        else
        {
            if (rv == CKR.CKR_OK)
            {
                eventOccured = true;
                slotId = (ulong)slotId_;
            }
            else
            {
                Pkcs11Exception.ThrowIfError(rv, "C_WaitForSlotEvent");
            }
        }
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

        Slot? matched = null;
        foreach (var slot in GetSlotList(SlotsType.WithTokenPresent))
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

        var session = matched.OpenSession(SessionType.ReadWrite);
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
    protected virtual void Dispose(bool disposing)
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