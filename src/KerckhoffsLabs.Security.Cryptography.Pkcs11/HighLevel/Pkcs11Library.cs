using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// High level PKCS#11 wrapper
/// </summary>
public class Pkcs11Library
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    protected bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private Pkcs11InteropLogger _logger = Pkcs11InteropLoggerFactory.GetLogger(typeof(Pkcs11Library));

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
        _logger.Debug("Pkcs11Library({0})::ctor", libraryPath);

        _libraryPath = libraryPath;

        try
        {
            _logger.Info("Loading PKCS#11 library {0}", _libraryPath);
            _pkcs11Library = new LowLevelPkcs11Library(_libraryPath, initType == InitType.WithFunctionList);
            Initialize(appType);
        }
        catch
        {
            if (_pkcs11Library != null)
            {
                _logger.Info("Unloading PKCS#11 library {0}", _libraryPath);
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
        _logger.Debug("Pkcs11Library({0})::Initialize", _libraryPath);

        CK_C_INITIALIZE_ARGS initArgs = null;
        if (appType == AppType.MultiThreaded)
        {
            initArgs = new CK_C_INITIALIZE_ARGS
            {
                Flags = CKF.CKF_OS_LOCKING_OK
            };
        }

        CKR rv = _pkcs11Library.C_Initialize(initArgs);
        if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
            throw new Pkcs11Exception("C_Initialize", rv);
    }

    /// <summary>
    /// Gets general information about loaded PKCS#11 library
    /// </summary>
    /// <returns>General information about loaded PKCS#11 library</returns>
    public LibraryInfo GetInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _logger.Debug("Pkcs11Library({0})::GetInfo", _libraryPath);

        CK_INFO info = new();
        CKR rv = _pkcs11Library.C_GetInfo(ref info);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetInfo", rv);

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

        _logger.Debug("Pkcs11Library({0})::GetSlotList", _libraryPath);

        NativeCULong slotCount = new (0);
        CKR rv = _pkcs11Library.C_GetSlotList(slotsType == SlotsType.WithTokenPresent, null, ref slotCount);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetSlotList", rv);

        if (slotCount.Value == 0)
        {
            return [];
        }
        else
        {
            NativeCULong[] slotList = new NativeCULong[slotCount.Value];
            rv = _pkcs11Library.C_GetSlotList(slotsType == SlotsType.WithTokenPresent, slotList, ref slotCount);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetSlotList", rv);

            if (new NativeCULong((uint)slotList.Length).Value != slotCount.Value)
                Array.Resize(ref slotList, ConvertUtils.UInt32ToInt32(slotCount));

            List<Slot> list = [];
            foreach (NativeCULong slot in slotList)
                list.Add(new Slot(_pkcs11Library, Convert.ToUInt64(slot)));

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
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Pkcs11Library({0})::WaitForSlotEvent", _libraryPath);

        NativeCULong flags = (waitType == WaitType.NonBlocking) ? CKF.CKF_DONT_BLOCK : new (0);

        NativeCULong slotId_ = new (0);
        CKR rv = _pkcs11Library.C_WaitForSlotEvent(flags, ref slotId_, IntPtr.Zero);
        if (waitType == WaitType.NonBlocking)
        {
            if (rv == CKR.CKR_OK)
            {
                eventOccured = true;
                slotId = Convert.ToUInt64(slotId_);
            }
            else if (rv == CKR.CKR_NO_EVENT)
            {
                eventOccured = false;
                slotId = Convert.ToUInt64(slotId_);
            }
            else
            {
                throw new Pkcs11Exception("C_WaitForSlotEvent", rv);
            }
        }
        else
        {
            if (rv == CKR.CKR_OK)
            {
                eventOccured = true;
                slotId = Convert.ToUInt64(slotId_);
            }
            else
            {
                throw new Pkcs11Exception("C_WaitForSlotEvent", rv);
            }
        }
    }

    #region IDisposable

    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        _logger.Debug("Pkcs11Library({0})::Dispose1", _libraryPath);

        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    protected virtual void Dispose(bool disposing)
    {
        _logger.Debug("Pkcs11Library({0})::Dispose2", _libraryPath);

        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed objects
                if (_pkcs11Library != null)
                {
                    _pkcs11Library.C_Finalize(IntPtr.Zero);

                    _logger.Info("Unloading PKCS#11 library {0}", _libraryPath);
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