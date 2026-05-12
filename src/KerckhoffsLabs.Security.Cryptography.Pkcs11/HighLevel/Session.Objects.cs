using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
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
}
