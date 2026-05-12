using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Class representing a logical connection between an application and a token
/// </summary>
public partial class Session
{
    /// <summary>
    /// Flag indicating whether instance has been disposed
    /// </summary>
    protected bool _disposed = false;

    /// <summary>
    /// Logger responsible for message logging
    /// </summary>
    private Pkcs11InteropLogger _logger = Pkcs11InteropLoggerFactory.GetLogger(typeof(Session));

    /// <summary>
    /// Low level PKCS#11 wrapper
    /// </summary>
    protected LowLevelPkcs11Library _pkcs11Library = null;

    /// <summary>
    /// PKCS#11 handle of session
    /// </summary>
    protected NativeCULong _sessionId = CK.CK_INVALID_HANDLE;

    /// <summary>
    /// PKCS#11 handle of session
    /// </summary>
    public ulong SessionId
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return (ulong)_sessionId;
        }
    }

    /// <summary>
    /// Flag indicating whether session should be closed when object is disposed
    /// </summary>
    protected bool _closeWhenDisposed = true;

    /// <summary>
    /// Flag indicating whether session should be closed when object is disposed
    /// </summary>
    public bool CloseWhenDisposed
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _closeWhenDisposed;
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _logger.Debug("Session({0})::CloseWhenDisposed", _sessionId);

            _closeWhenDisposed = value;
        }
    }

    /// <summary>Backing field for <see cref="AllowInsecure"/>.</summary>
    protected bool _allowInsecure = false;

    /// <summary>
    /// When <c>true</c>, this session does not reject operations that use mechanisms flagged as
    /// insecure by default (RSA PKCS#1 v1.5, DES/3DES, AES-ECB, etc.). Default is <c>false</c>.
    /// Set explicitly per session; never set this globally.
    /// </summary>
    public bool AllowInsecure
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            return _allowInsecure;
        }
        set
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            _allowInsecure = value;
        }
    }

    /// <summary>
    /// Initializes new instance of Session class
    /// </summary>
    /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
    /// <param name="sessionId">PKCS#11 handle of session</param>
    protected internal Session(LowLevelPkcs11Library pkcs11Library, ulong sessionId)
    {
        _logger.Debug("Session({0})::ctor", sessionId);

        if (pkcs11Library == null)
            throw new ArgumentNullException("pkcs11Library");

        if (sessionId == (ulong)CK.CK_INVALID_HANDLE)
            throw new ArgumentException("Invalid handle specified", "sessionId");

        _pkcs11Library = pkcs11Library;
        _sessionId = (NativeCULong)(sessionId);
    }

    /// <summary>
    /// Closes a session between an application and a token
    /// </summary>
    public void CloseSession()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::CloseSession", _sessionId);

        _logger.Info("Closing session {0}", _sessionId);

        CKR rv = _pkcs11Library.C_CloseSession(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_CloseSession", rv);

        _sessionId = CK.CK_INVALID_HANDLE;
    }

    /// <summary>
    /// Initializes the normal user's PIN
    /// </summary>
    /// <param name="userPin">Pin value</param>
    public void InitPin(string userPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::InitPin1", _sessionId);

        byte[] pinValue = null;
        NativeCULong pinValueLen = (NativeCULong)0;
        if (userPin != null)
        {
            pinValue = System.Text.Encoding.UTF8.GetBytes(userPin);
            pinValueLen = (NativeCULong)(pinValue.Length);
        }

        CKR rv = _pkcs11Library.C_InitPIN(_sessionId, pinValue, pinValueLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_InitPIN", rv);
    }

    /// <summary>
    /// Initializes the normal user's PIN
    /// </summary>
    /// <param name="userPin">Pin value</param>
    public void InitPin(byte[] userPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::InitPin2", _sessionId);

        byte[] pinValue = null;
        NativeCULong pinValueLen = (NativeCULong)0;
        if (userPin != null)
        {
            pinValue = userPin;
            pinValueLen = (NativeCULong)(userPin.Length);
        }
        
        CKR rv = _pkcs11Library.C_InitPIN(_sessionId, pinValue, pinValueLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_InitPIN", rv);
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
    /// </summary>
    /// <param name="oldPin">Old PIN value</param>
    /// <param name="newPin">New PIN value</param>
    public void SetPin(string oldPin, string newPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SetPin1", _sessionId);

        byte[] oldPinValue = null;
        NativeCULong oldPinValueLen = (NativeCULong)0;
        if (oldPin != null)
        {
            oldPinValue = System.Text.Encoding.UTF8.GetBytes(oldPin);
            oldPinValueLen = (NativeCULong)(oldPinValue.Length);
        }

        byte[] newPinValue = null;
        NativeCULong newPinValueLen = (NativeCULong)0;
        if (newPin != null)
        {
            newPinValue = System.Text.Encoding.UTF8.GetBytes(newPin);
            newPinValueLen = (NativeCULong)(newPinValue.Length);
        }

        CKR rv = _pkcs11Library.C_SetPIN(_sessionId, oldPinValue, oldPinValueLen, newPinValue, newPinValueLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SetPIN", rv);
    }

    /// <summary>
    /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
    /// </summary>
    /// <param name="oldPin">Old PIN value</param>
    /// <param name="newPin">New PIN value</param>
    public void SetPin(byte[] oldPin, byte[] newPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SetPin2", _sessionId);

        byte[] oldPinValue = null;
        NativeCULong oldPinValueLen = (NativeCULong)0;
        if (oldPin != null)
        {
            oldPinValue = oldPin;
            oldPinValueLen = (NativeCULong)(oldPin.Length);
        }
        
        byte[] newPinValue = null;
        NativeCULong newPinValueLen = (NativeCULong)0;
        if (newPin != null)
        {
            newPinValue = newPin;
            newPinValueLen = (NativeCULong)(newPin.Length);
        }
        
        CKR rv = _pkcs11Library.C_SetPIN(_sessionId, oldPinValue, oldPinValueLen, newPinValue, newPinValueLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SetPIN", rv);
    }

    /// <summary>
    /// Obtains information about a session
    /// </summary>
    /// <returns>Information about a session</returns>
    public SessionInfo GetSessionInfo()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetSessionInfo", _sessionId);

        CK_SESSION_INFO sessionInfo = new CK_SESSION_INFO();
        CKR rv = _pkcs11Library.C_GetSessionInfo(_sessionId, ref sessionInfo);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetSessionInfo", rv);

        return new SessionInfo(_sessionId, sessionInfo);
    }

    /// <summary>
    /// Obtains a copy of the cryptographic operations state of a session encoded as an array of bytes
    /// </summary>
    /// <returns>Operations state of a session</returns>
    public byte[] GetOperationState()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetOperationState", _sessionId);

        NativeCULong operationStateLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetOperationState(_sessionId, null, ref operationStateLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetOperationState", rv);

        byte[] operationState = new byte[(int)operationStateLen];
        rv = _pkcs11Library.C_GetOperationState(_sessionId, operationState, ref operationStateLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetOperationState", rv);

        return operationState;
    }

    /// <summary>
    /// Restores the cryptographic operations state of a session from an array of bytes obtained with GetOperationState
    /// </summary>
    /// <param name="state">Array of bytes obtained with GetOperationState</param>
    /// <param name="encryptionKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing encryption or decryption operation in the restored session</param>
    /// <param name="authenticationKey">CK_INVALID_HANDLE or handle to the key which will be used for an ongoing signature, MACing, or verification operation in the restored session</param>
    public void SetOperationState(byte[] state, ObjectHandle encryptionKey, ObjectHandle authenticationKey)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SetOperationState", _sessionId);

        if (state == null)
            throw new ArgumentNullException("state");

        if (encryptionKey == null)
            throw new ArgumentNullException("encryptionKey");

        if (authenticationKey == null)
            throw new ArgumentNullException("authenticationKey");

        CKR rv = _pkcs11Library.C_SetOperationState(_sessionId, state, (NativeCULong)(state.Length), (NativeCULong)(encryptionKey.ObjectId), (NativeCULong)(authenticationKey.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SetOperationState", rv);
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="userType">Type of user</param>
    /// <param name="pin">Pin of user</param>
    public void Login(CKU userType, string pin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Login1", _sessionId);

        if (_logger.IsEnabled(Pkcs11InteropLogLevel.Info))
            _logger.Info("Logging as {0} into session {1}", Pkcs11InteropLogUtils.ToString(userType), _sessionId);

        byte[] pinValue = null;
        NativeCULong pinValueLen = (NativeCULong)0;
        if (pin != null)
        {
            pinValue = System.Text.Encoding.UTF8.GetBytes(pin);
            pinValueLen = (NativeCULong)(pinValue.Length);
        }

        CKR rv = _pkcs11Library.C_Login(_sessionId, userType, pinValue, pinValueLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Login", rv);
    }

    /// <summary>
    /// Logs a user into a token
    /// </summary>
    /// <param name="userType">Type of user</param>
    /// <param name="pin">Pin of user</param>
    public void Login(CKU userType, byte[] pin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Login2", _sessionId);

        if (_logger.IsEnabled(Pkcs11InteropLogLevel.Info))
            _logger.Info("Logging as {0} into session {1}", Pkcs11InteropLogUtils.ToString(userType), _sessionId);

        byte[] pinValue = null;
        NativeCULong pinValueLen = (NativeCULong)0;
        if (pin != null)
        {
            pinValue = pin;
            pinValueLen = (NativeCULong)(pin.Length);
        }

        CKR rv = _pkcs11Library.C_Login(_sessionId, userType, pinValue, pinValueLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Login", rv);
    }

    /// <summary>
    /// Logs a user out from a token
    /// </summary>
    public void Logout()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Logout", _sessionId);

        _logger.Info("Logging out of session {0}", _sessionId);

        CKR rv = _pkcs11Library.C_Logout(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Logout", rv);
    }

    /// <summary>
    /// Creates a new object
    /// </summary>
    /// <param name="attributes">Object attributes</param>
    /// <returns>Handle of created object</returns>
    public ObjectHandle CreateObject(List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::CreateObject", _sessionId);

        NativeCULong objectId = CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLength = (NativeCULong)0;
        
        if (attributes != null)
        {
            templateLength = (NativeCULong)(attributes.Count);
            template = new CK_ATTRIBUTE[(int)templateLength];
            for (int i = 0; i < (int)(templateLength); i++)
                template[i] = attributes[i].CkAttribute;
        }

        CKR rv = _pkcs11Library.C_CreateObject(_sessionId, template, templateLength, ref objectId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_CreateObject", rv);

        return new ObjectHandle((ulong)objectId);
    }

    /// <summary>
    /// Copies an object, creating a new object for the copy
    /// </summary>
    /// <param name="objectHandle">Handle of object to be copied</param>
    /// <param name="attributes">New values for any attributes of the object that can ordinarily be modified</param>
    /// <returns>Handle of copied object</returns>
    public ObjectHandle CopyObject(ObjectHandle objectHandle, List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::CopyObject", _sessionId);

        if (objectHandle == null)
            throw new ArgumentNullException("objectHandle");

        NativeCULong objectId = CK.CK_INVALID_HANDLE;

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLength = (NativeCULong)0;

        if (attributes != null)
        {
            templateLength = (NativeCULong)(attributes.Count);
            template = new CK_ATTRIBUTE[(int)templateLength];
            for (int i = 0; i < (int)(templateLength); i++)
                template[i] = attributes[i].CkAttribute;
        }

        CKR rv = _pkcs11Library.C_CopyObject(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, templateLength, ref objectId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_CopyObject", rv);

        return new ObjectHandle((ulong)objectId);
    }

    /// <summary>
    /// Destroys an object
    /// </summary>
    /// <param name="objectHandle">Handle of object to be destroyed</param>
    public void DestroyObject(ObjectHandle objectHandle)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::DestroyObject", _sessionId);

        if (objectHandle == null)
            throw new ArgumentNullException("objectHandle");

        CKR rv = _pkcs11Library.C_DestroyObject(_sessionId, (NativeCULong)(objectHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_DestroyObject", rv);
    }

    /// <summary>
    /// Gets the size of an object in bytes.
    /// </summary>
    /// <param name="objectHandle">Handle of object</param>
    /// <returns>Size of an object in bytes</returns>
    public ulong GetObjectSize(ObjectHandle objectHandle)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetObjectSize", _sessionId);

        if (objectHandle == null)
            throw new ArgumentNullException("objectHandle");

        NativeCULong objectSize = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_GetObjectSize(_sessionId, (NativeCULong)(objectHandle.ObjectId), ref objectSize);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetObjectSize", rv);

        return (ulong)(objectSize);
    }

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be read</param>
    /// <param name="attributes">List of attributes that should be read</param>
    /// <returns>Object attributes</returns>
    public List<ObjectAttribute> GetAttributeValue(ObjectHandle objectHandle, List<CKA> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetAttributeValue1", _sessionId);

        if (objectHandle == null)
            throw new ArgumentNullException("objectHandle");

        if (attributes == null)
            throw new ArgumentNullException("attributes");

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", "attributes");

        List<ulong> ulongs = new List<ulong>();
        foreach (CKA attribute in attributes)
            ulongs.Add((ulong)attribute.ToCULong());

        return GetAttributeValue(objectHandle, ulongs);
    }

    /// <summary>
    /// Obtains the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be read</param>
    /// <param name="attributes">List of attributes that should be read</param>
    /// <returns>Object attributes</returns>
    public List<ObjectAttribute> GetAttributeValue(ObjectHandle objectHandle, List<ulong> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetAttributeValue2", _sessionId);

        if (objectHandle == null)
            throw new ArgumentNullException("objectHandle");

        if (attributes == null)
            throw new ArgumentNullException("attributes");

        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", "attributes");

        // Prepare array of CK_ATTRIBUTEs
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
            template[i] = new ObjectAttribute(attributes[i]).CkAttribute;

        // Determine size of attribute values
        CKR rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
        if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_ATTRIBUTE_SENSITIVE) && (rv != CKR.CKR_ATTRIBUTE_TYPE_INVALID))
            throw new Pkcs11Exception("C_GetAttributeValue", rv);

        // Allocate memory for each attribute
        for (int i = 0; i < template.Length; i++)
        {
            // PKCS#11 v2.20 page 133:
            // If the specified attribute (i.e., the attribute specified by the type field) for the object
            // cannot be revealed because the object is sensitive or unextractable, then the
            // ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
            // CK_LONG, it holds -1).
            if (template[i].valueLen.Value != nuint.MaxValue)
                template[i].value = UnmanagedMemory.Allocate((int)(template[i].valueLen));
        }

        // Read values of attributes
        rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
        if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_ATTRIBUTE_SENSITIVE) && (rv != CKR.CKR_ATTRIBUTE_TYPE_INVALID))
            throw new Pkcs11Exception("C_GetAttributeValue", rv);

        // Third call to C_GetAttributeValue is needed if any of the attributes is an array attribute
        bool thirdCallNeeded = false;
        for (int i = 0; i < template.Length; i++)
        {
            if (MiscSettings.AttributesWithNestedAttributes.ContainsKey((ulong)(template[i].type)))
            {
                // PKCS#11 v2.20 page 133:
                // If the specified attribute (i.e., the attribute specified by the type field) for the object
                // cannot be revealed because the object is sensitive or unextractable, then the
                // ulValueLen field in that triple is modified to hold the value -1 (i.e., when it is cast to a
                // CK_LONG, it holds -1).
                if (template[i].valueLen.Value == nuint.MaxValue)
                    continue;

                int ckAttributeSize = UnmanagedMemory.SizeOf(typeof(CK_ATTRIBUTE));
                int nestedAttrCount = (int)(template[i].valueLen) / ckAttributeSize;
                int nestedAttrCountMod = (int)(template[i].valueLen) % ckAttributeSize;

                if (nestedAttrCountMod != 0)
                    throw new Exception("Unable to read attribute value as attribute array");

                if (nestedAttrCount == 0)
                {
                    continue;
                }
                else
                {
                    thirdCallNeeded = true;

                    // Allocate memory for each nested attribute
                    for (int j = 0; j < nestedAttrCount; j++)
                    {
                        IntPtr tempPointer = new IntPtr(template[i].value.ToInt64() + (j * ckAttributeSize));
                        CK_ATTRIBUTE tempAttribute = (CK_ATTRIBUTE)UnmanagedMemory.Read(tempPointer, typeof(CK_ATTRIBUTE));

                        if (tempAttribute.valueLen.Value != nuint.MaxValue)
                            tempAttribute.value = UnmanagedMemory.Allocate((int)(tempAttribute.valueLen));

                        UnmanagedMemory.Write(tempPointer, tempAttribute);
                    }
                }
            }
        }

        // Read values of all nested attributes
        if (thirdCallNeeded)
        {
            rv = _pkcs11Library.C_GetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
            if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_ATTRIBUTE_SENSITIVE) && (rv != CKR.CKR_ATTRIBUTE_TYPE_INVALID))
                throw new Pkcs11Exception("C_GetAttributeValue", rv);
        }

        // Convert CK_ATTRIBUTEs to ObjectAttributes
        List<ObjectAttribute> outAttributes = new List<ObjectAttribute>();
        for (int i = 0; i < template.Length; i++)
            outAttributes.Add(new ObjectAttribute(template[i]));

        return outAttributes;
    }

    /// <summary>
    /// Modifies the value of one or more attributes of an object
    /// </summary>
    /// <param name="objectHandle">Handle of object whose attributes should be modified</param>
    /// <param name="attributes">List of attributes that should be modified</param>
    public void SetAttributeValue(ObjectHandle objectHandle, List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SetAttributeValue", _sessionId);

        if (objectHandle == null)
            throw new ArgumentNullException("objectHandle");

        if (attributes == null)
            throw new ArgumentNullException("attributes");
        
        if (attributes.Count < 1)
            throw new ArgumentException("No attributes specified", "attributes");

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributes.Count];
        for (int i = 0; i < attributes.Count; i++)
            template[i] = attributes[i].CkAttribute;

        CKR rv = _pkcs11Library.C_SetAttributeValue(_sessionId, (NativeCULong)(objectHandle.ObjectId), template, (NativeCULong)(template.Length));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SetAttributeValue", rv);
    }

    /// <summary>
    /// Initializes a search for token and session objects that match a attributes
    /// </summary>
    /// <param name="attributes">Attributes that should be matched</param>
    public void FindObjectsInit(List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::FindObjectsInit", _sessionId);

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLength = (NativeCULong)0;
        
        if (attributes != null)
        {
            templateLength = (NativeCULong)(attributes.Count);
            template = new CK_ATTRIBUTE[(int)templateLength];
            for (int i = 0; i < (int)(templateLength); i++)
                template[i] = attributes[i].CkAttribute;
        }

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template, templateLength);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_FindObjectsInit", rv);
    }

    /// <summary>
    /// Continues a search for token and session objects that match a template, obtaining additional object handles
    /// </summary>
    /// <param name="objectCount">Maximum number of object handles to be returned</param>
    /// <returns>Found object handles</returns>
    public List<ObjectHandle> FindObjects(int objectCount)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::FindObjects", _sessionId);

        List<ObjectHandle> foundObjects = new List<ObjectHandle>();

        NativeCULong[] objects = new NativeCULong[objectCount];
        NativeCULong foundObjectsCount = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_FindObjects(_sessionId, objects, (NativeCULong)(objectCount), ref foundObjectsCount);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_FindObjects", rv);

        for (int i = 0; i < (int)(foundObjectsCount); i++)
            foundObjects.Add(new ObjectHandle((ulong)objects[i]));

        return foundObjects;
    }

    /// <summary>
    /// Terminates a search for token and session objects
    /// </summary>
    public void FindObjectsFinal()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::FindObjectsFinal", _sessionId);

        CKR rv = _pkcs11Library.C_FindObjectsFinal(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_FindObjectsFinal", rv);
    }

    /// <summary>
    /// Searches for all token and session objects that match provided attributes
    /// </summary>
    /// <param name="attributes">Attributes that should be matched</param>
    /// <returns>Handles of found objects</returns>
    public List<ObjectHandle> FindAllObjects(List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::FindAllObjects", _sessionId);

        List<ObjectHandle> foundObjects = new List<ObjectHandle>();

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLength = (NativeCULong)0;
        
        if (attributes != null)
        {
            templateLength = (NativeCULong)(attributes.Count);
            template = new CK_ATTRIBUTE[(int)templateLength];
            for (int i = 0; i < (int)(templateLength); i++)
                template[i] = attributes[i].CkAttribute;
        }

        CKR rv = _pkcs11Library.C_FindObjectsInit(_sessionId, template, templateLength);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_FindObjectsInit", rv);

        NativeCULong objectsLength = (NativeCULong)256;
        NativeCULong[] objects = new NativeCULong[(int)objectsLength];
        NativeCULong objectCount = objectsLength;
        while (objectCount == objectsLength)
        {
            rv = _pkcs11Library.C_FindObjects(_sessionId, objects, objectsLength, ref objectCount);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_FindObjects", rv);

            for (int i = 0; i < (int)(objectCount); i++)
                foundObjects.Add(new ObjectHandle((ulong)objects[i]));
        }

        rv = _pkcs11Library.C_FindObjectsFinal(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_FindObjectsFinal", rv);

        return foundObjects;
    }

    /// <summary>
    /// Generates a secret key or set of domain parameters, creating a new object
    /// </summary>
    /// <param name="mechanism">Generation mechanism</param>
    /// <param name="attributes">Attributes of the new key or set of domain parameters</param>
    /// <returns>Handle of the new key or set of domain parameters</returns>
    public ObjectHandle GenerateKey(Mechanism mechanism, List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GenerateKey", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLength = (NativeCULong)0;
        
        if (attributes != null)
        {
            templateLength = (NativeCULong)(attributes.Count);
            template = new CK_ATTRIBUTE[(int)templateLength];
            for (int i = 0; i < (int)(templateLength); i++)
                template[i] = attributes[i].CkAttribute;
        }

        NativeCULong keyId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_GenerateKey(_sessionId, ref ckMechanism, template, templateLength, ref keyId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GenerateKey", rv);

        return new ObjectHandle((ulong)keyId);
    }

    /// <summary>
    /// Generates a public/private key pair, creating new key objects
    /// </summary>
    /// <param name="mechanism">Key generation mechanism</param>
    /// <param name="publicKeyAttributes">Attributes of the public key</param>
    /// <param name="privateKeyAttributes">Attributes of the private key</param>
    /// <param name="publicKeyHandle">Handle of the new public key</param>
    /// <param name="privateKeyHandle">Handle of the new private key</param>
    public void GenerateKeyPair(Mechanism mechanism, List<ObjectAttribute> publicKeyAttributes, List<ObjectAttribute> privateKeyAttributes, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GenerateKeyPair", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[] publicKeyTemplate = null;
        NativeCULong publicKeyTemplateLength = (NativeCULong)0;
        
        if (publicKeyAttributes != null)
        {
            publicKeyTemplateLength = (NativeCULong)(publicKeyAttributes.Count);
            publicKeyTemplate = new CK_ATTRIBUTE[(int)publicKeyTemplateLength];
            for (int i = 0; i < (int)(publicKeyTemplateLength); i++)
                publicKeyTemplate[i] = publicKeyAttributes[i].CkAttribute;
        }

        CK_ATTRIBUTE[] privateKeyTemplate = null;
        NativeCULong privateKeyTemplateLength = (NativeCULong)0;

        if (privateKeyAttributes != null)
        {
            privateKeyTemplateLength = (NativeCULong)(privateKeyAttributes.Count);
            privateKeyTemplate = new CK_ATTRIBUTE[(int)privateKeyTemplateLength];
            for (int i = 0; i < (int)(privateKeyTemplateLength); i++)
                privateKeyTemplate[i] = privateKeyAttributes[i].CkAttribute;
        }

        NativeCULong publicKeyId = CK.CK_INVALID_HANDLE;
        NativeCULong privateKeyId = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_GenerateKeyPair(_sessionId, ref ckMechanism, publicKeyTemplate, publicKeyTemplateLength, privateKeyTemplate, privateKeyTemplateLength, ref publicKeyId, ref privateKeyId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GenerateKeyPair", rv);

        publicKeyHandle = new ObjectHandle((ulong)publicKeyId);
        privateKeyHandle = new ObjectHandle((ulong)privateKeyId);
    }

    /// <summary>
    /// Wraps (i.e., encrypts) a private or secret key
    /// </summary>
    /// <param name="mechanism">Wrapping mechanism</param>
    /// <param name="wrappingKeyHandle">Handle of wrapping key</param>
    /// <param name="keyHandle">Handle of key to be wrapped</param>
    /// <returns>Wrapped key</returns>
    public byte[] WrapKey(Mechanism mechanism, ObjectHandle wrappingKeyHandle, ObjectHandle keyHandle)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::WrapKey", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");
        
        if (wrappingKeyHandle == null)
            throw new ArgumentNullException("wrappingKeyHandle");
        
        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        NativeCULong wrappedKeyLen = (NativeCULong)0;
        CKR rv = _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), null, ref wrappedKeyLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_WrapKey", rv);

        byte[] wrappedKey = new byte[(int)wrappedKeyLen];
        rv = _pkcs11Library.C_WrapKey(_sessionId, ref ckMechanism, (NativeCULong)(wrappingKeyHandle.ObjectId), (NativeCULong)(keyHandle.ObjectId), wrappedKey, ref wrappedKeyLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_WrapKey", rv);

        if (wrappedKey.Length != (int)(wrappedKeyLen))
            Array.Resize(ref wrappedKey, (int)(wrappedKeyLen));

        return wrappedKey;
    }

    /// <summary>
    /// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object
    /// </summary>
    /// <param name="mechanism">Unwrapping mechanism</param>
    /// <param name="unwrappingKeyHandle">Handle of unwrapping key</param>
    /// <param name="wrappedKey">Wrapped key</param>
    /// <param name="attributes">Attributes for unwrapped key</param>
    /// <returns>Handle of unwrapped key</returns>
    public ObjectHandle UnwrapKey(Mechanism mechanism, ObjectHandle unwrappingKeyHandle, byte[] wrappedKey, List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::UnwrapKey", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");
        
        if (unwrappingKeyHandle == null)
            throw new ArgumentNullException("unwrappingKeyHandle");
        
        if (wrappedKey == null)
            throw new ArgumentNullException("wrappedKey");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLen = (NativeCULong)0;
        if (attributes != null)
        {
            template = new CK_ATTRIBUTE[attributes.Count];
            for (int i = 0; i < attributes.Count; i++)
                template[i] = attributes[i].CkAttribute;
            templateLen = (NativeCULong)(attributes.Count);
        }

        NativeCULong unwrappedKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_UnwrapKey(_sessionId, ref ckMechanism, (NativeCULong)(unwrappingKeyHandle.ObjectId), wrappedKey, (NativeCULong)(wrappedKey.Length), template, templateLen, ref unwrappedKey);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_UnwrapKey", rv);

        return new ObjectHandle((ulong)unwrappedKey);
    }

    /// <summary>
    /// Derives a key from a base key, creating a new key object
    /// </summary>
    /// <param name="mechanism">Derivation mechanism</param>
    /// <param name="baseKeyHandle">Handle of base key</param>
    /// <param name="attributes">Attributes for the new key</param>
    /// <returns>Handle of derived key</returns>
    public ObjectHandle DeriveKey(Mechanism mechanism, ObjectHandle baseKeyHandle, List<ObjectAttribute> attributes)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::DeriveKey", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");
        
        if (baseKeyHandle == null)
            throw new ArgumentNullException("baseKeyHandle");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CK_ATTRIBUTE[] template = null;
        NativeCULong templateLen = (NativeCULong)0;
        if (attributes != null)
        {
            template = new CK_ATTRIBUTE[attributes.Count];
            for (int i = 0; i < attributes.Count; i++)
                template[i] = attributes[i].CkAttribute;
            templateLen = (NativeCULong)(attributes.Count);
        }

        NativeCULong derivedKey = CK.CK_INVALID_HANDLE;
        CKR rv = _pkcs11Library.C_DeriveKey(_sessionId, ref ckMechanism, (NativeCULong)(baseKeyHandle.ObjectId), template, templateLen, ref derivedKey);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_DeriveKey", rv);

        return new ObjectHandle((ulong)derivedKey);
    }

    /// <summary>
    /// Mixes additional seed material into the token's random number generator
    /// </summary>
    /// <param name="seed">Seed material</param>
    public void SeedRandom(byte[] seed)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::SeedRandom", _sessionId);

        if (seed == null)
            throw new ArgumentNullException("seed");

        CKR rv = _pkcs11Library.C_SeedRandom(_sessionId, seed, (NativeCULong)(seed.Length));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SeedRandom", rv);
    }

    /// <summary>
    /// Generates random or pseudo-random data
    /// </summary>
    /// <param name="length">Length in bytes of the random or pseudo-random data to be generated</param>
    /// <returns>Generated random or pseudo-random data</returns>
    public byte[] GenerateRandom(int length)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GenerateRandom", _sessionId);

        if (length < 1)
            throw new ArgumentException("Value has to be positive number", "length");

        byte[] randomData = new byte[length];
        CKR rv = _pkcs11Library.C_GenerateRandom(_sessionId, randomData, (NativeCULong)(length));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GenerateRandom", rv);

        return randomData;
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void GetFunctionStatus()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::GetFunctionStatus", _sessionId);

        CKR rv = _pkcs11Library.C_GetFunctionStatus(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_GetFunctionStatus", rv);
    }

    /// <summary>
    /// Legacy function which should throw CKR_FUNCTION_NOT_PARALLEL
    /// </summary>
    public void CancelFunction()
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::CancelFunction", _sessionId);

        CKR rv = _pkcs11Library.C_CancelFunction(_sessionId);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_CancelFunction", rv);
    }

    /// <summary>
    /// Checks the given mechanism against the insecure-mechanism set and throws
    /// <see cref="InsecureOperationException"/> if it is insecure and <see cref="AllowInsecure"/>
    /// is false.
    /// </summary>
    private void GuardMechanism(CKM mechanism)
    {
        if (AllowInsecure) return;

        switch (mechanism)
        {
            case CKM.CKM_RSA_PKCS:
                throw new InsecureOperationException(mechanism,
                    "RSA PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks and fault attacks; use CKM_RSA_PKCS_OAEP for encryption or CKM_RSA_PKCS_PSS for signing.");
            case CKM.CKM_MD5_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS:
            case CKM.CKM_SHA1_RSA_PKCS_PSS:
                throw new InsecureOperationException(mechanism,
                    "MD5/SHA-1 in RSA signature contexts is broken (SHAttered breaks PSS-SHA-1 too); use CKM_SHA256_RSA_PKCS_PSS or CKM_ECDSA_SHA256 instead.");
            case CKM.CKM_MD5:
            case CKM.CKM_SHA_1:
                throw new InsecureOperationException(mechanism,
                    "MD5 and SHA-1 are broken hash functions; use CKM_SHA256 or stronger.");
            case CKM.CKM_DES_ECB:
            case CKM.CKM_DES_CBC:
            case CKM.CKM_DES_CBC_PAD:
            case CKM.CKM_DES3_ECB:
            case CKM.CKM_DES3_CBC:
            case CKM.CKM_DES3_CBC_PAD:
                throw new InsecureOperationException(mechanism,
                    "DES and 3DES are deprecated; use AES (CKM_AES_GCM or CKM_AES_CBC_PAD) instead.");
            case CKM.CKM_DES_MAC:
            case CKM.CKM_DES_MAC_GENERAL:
            case CKM.CKM_DES3_MAC:
            case CKM.CKM_DES3_MAC_GENERAL:
                throw new InsecureOperationException(mechanism,
                    "DES/3DES MAC is weak; use CKM_AES_CMAC or CKM_SHA256_HMAC instead.");
            case CKM.CKM_AES_ECB:
                throw new InsecureOperationException(mechanism,
                    "ECB mode leaks structural information from the plaintext; use CKM_AES_GCM or CKM_AES_CBC_PAD instead.");
            default:
                return;
        }
    }

    #region IDisposable

    /// <summary>
    /// Disposes object
    /// </summary>
    public void Dispose()
    {
        _logger.Debug("Session({0})::Dispose1", _sessionId);

        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes object
    /// </summary>
    /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
    protected virtual void Dispose(bool disposing)
    {
        _logger.Debug("Session({0})::Dispose2", _sessionId);

        if (!_disposed)
        {
            if (disposing)
            {
                // Dispose managed objects
                if (_sessionId != CK.CK_INVALID_HANDLE && _closeWhenDisposed == true)
                    CloseSession();
            }

            // Dispose unmanaged objects
            _disposed = true;
        }
    }

    /// <summary>
    /// Class destructor that disposes object if caller forgot to do so
    /// </summary>
    ~Session()
    {
        Dispose(false);
    }

    #endregion
}