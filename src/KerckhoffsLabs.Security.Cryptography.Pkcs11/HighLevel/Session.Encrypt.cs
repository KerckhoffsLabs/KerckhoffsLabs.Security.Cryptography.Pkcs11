using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    /// <summary>
    /// Encrypts <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">The encryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to encrypt with.</param>
    /// <param name="data">Plaintext to encrypt.</param>
    /// <returns>A freshly-allocated byte array containing the ciphertext.</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Encrypt(mechanism, keyHandle, buffer);
    }

    /// <summary>
    /// Encrypts single-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be encrypted</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Encrypt1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_EncryptInit", rv);

        NativeCULong encryptedDataLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)(data.Length), null, ref encryptedDataLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Encrypt", rv);

        byte[] encryptedData = new byte[(int)encryptedDataLen];
        rv = _pkcs11Library.C_Encrypt(_sessionId, data, (NativeCULong)(data.Length), encryptedData, ref encryptedDataLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Encrypt", rv);

        if (encryptedData.Length != (int)(encryptedDataLen))
            Array.Resize(ref encryptedData, (int)(encryptedDataLen));

        return encryptedData;
    }

    /// <summary>
    /// Encrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be encrypted should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Encrypt2", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        Encrypt(mechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Encrypts multi-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be encrypted should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Encrypt(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Encrypt3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_EncryptInit", rv);

        byte[] part = new byte[bufferLength];
        byte[] encryptedPart = new byte[bufferLength];
        NativeCULong encryptedPartLen = (NativeCULong)(encryptedPart.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            encryptedPartLen = (NativeCULong)(encryptedPart.Length);
            rv = _pkcs11Library.C_EncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                throw new Pkcs11Exception("C_EncryptUpdate", rv);

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                encryptedPart = new byte[(int)encryptedPartLen];

                rv = _pkcs11Library.C_EncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EncryptUpdate", rv);
            }

            outputStream.Write(encryptedPart, 0, (int)(encryptedPartLen));
        }

        byte[] lastEncryptedPart = null;
        NativeCULong lastEncryptedPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, null, ref lastEncryptedPartLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_EncryptFinal", rv);

        lastEncryptedPart = new byte[(int)lastEncryptedPartLen];
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, ref lastEncryptedPartLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_EncryptFinal", rv);

        if (lastEncryptedPartLen > (NativeCULong)0)
            outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));
    }
}
