using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    /// <summary>
    /// Decrypts single-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="encryptedData">Data to be decrypted</param>
    /// <returns>Decrypted data</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] encryptedData)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Decrypt1", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        if (encryptedData == null)
            throw new ArgumentNullException("encryptedData");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_DecryptInit", rv);

        NativeCULong decryptedDataLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, (NativeCULong)(encryptedData.Length), null, ref decryptedDataLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Decrypt", rv);

        byte[] decryptedData = new byte[(int)decryptedDataLen];
        rv = _pkcs11Library.C_Decrypt(_sessionId, encryptedData, (NativeCULong)(encryptedData.Length), decryptedData, ref decryptedDataLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Decrypt", rv);

        if (decryptedData.Length != (int)(decryptedDataLen))
            Array.Resize(ref decryptedData, (int)(decryptedDataLen));

        return decryptedData;
    }

    /// <summary>
    /// Decrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which encrypted data should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    public void Decrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Decrypt2", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        Decrypt(mechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Decrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which encrypted data should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Decrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        _logger.Debug("Session({0})::Decrypt3", _sessionId);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_DecryptInit", rv);

        byte[] encryptedPart = new byte[bufferLength];
        byte[] part = new byte[bufferLength];
        NativeCULong partLen = (NativeCULong)(part.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
        {
            partLen = (NativeCULong)(part.Length);
            rv = _pkcs11Library.C_DecryptUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                throw new Pkcs11Exception("C_DecryptUpdate", rv);

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                part = new byte[(int)partLen];

                rv = _pkcs11Library.C_DecryptUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_DecryptUpdate", rv);
            }

            outputStream.Write(part, 0, (int)(partLen));
        }

        byte[] lastPart = null;
        NativeCULong lastPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_DecryptFinal", rv);

        lastPart = new byte[(int)lastPartLen];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_DecryptFinal", rv);

        if (lastPartLen > (NativeCULong)0)
            outputStream.Write(lastPart, 0, (int)(lastPartLen));
    }
}
