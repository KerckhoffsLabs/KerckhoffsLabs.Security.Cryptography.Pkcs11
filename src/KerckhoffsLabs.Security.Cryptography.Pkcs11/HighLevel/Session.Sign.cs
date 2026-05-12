using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    /// <summary>
    /// Signs single-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="performLogin">Flag indicating whether context specific login should be performed</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <returns>Signature</returns>
    protected byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] data, bool performLogin, byte[] keyPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignInit", rv);

        if (performLogin)
        {
            byte[] pinValue = null;
            NativeCULong pinValueLen = (NativeCULong)0;
            if (keyPin != null)
            {
                pinValue = keyPin;
                pinValueLen = (NativeCULong)(keyPin.Length);
            }

            rv = _pkcs11Library.C_Login(_sessionId, CKU.CKU_CONTEXT_SPECIFIC, pinValue, pinValueLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Login", rv);
        }

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Sign(_sessionId, data, (NativeCULong)(data.Length), null, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Sign", rv);

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_Sign(_sessionId, data, (NativeCULong)(data.Length), signature, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_Sign", rv);

        if (signature.Length != (int)(signatureLen))
            Array.Resize(ref signature, (int)(signatureLen));

        return signature;
    }

    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="InsecureOperationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Signing mechanism.</param>
    /// <param name="keyHandle">Handle of the private/MAC key.</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (size depends on key + mechanism).</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        // Temporary array for the byte[]-based P/Invoke path. Replace with pinned-Span
        // P/Invoke when perf profiling proves it matters.
        byte[] buffer = data.ToArray();
        return Sign(mechanism, keyHandle, buffer);
    }

    /// <summary>
    /// Signs single-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="data">Data to be signed</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign1a", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return Sign(mechanism, keyHandle, data, false, null);
    }

    /// <summary>String-keyPin variant — see <see cref="Sign(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>.</summary>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, string keyPin, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        byte[] buffer = data.ToArray();
        return Sign(mechanism, keyHandle, keyPin, buffer);
    }

    /// <summary>
    /// Signs single-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="data">Data to be signed</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, string keyPin, byte[] data)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign1b", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return Sign(mechanism, keyHandle, data, true, System.Text.Encoding.UTF8.GetBytes(keyPin));
    }

    /// <summary>byte[]-keyPin variant — see <see cref="Sign(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>.</summary>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] keyPin, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        byte[] buffer = data.ToArray();
        return Sign(mechanism, keyHandle, keyPin, buffer);
    }

    /// <summary>
    /// Signs single-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="data">Data to be signed</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] keyPin, byte[] data)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign1c", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return Sign(mechanism, keyHandle, data, true, keyPin);
    }

    /// <summary>
    /// Signs multi-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign2a", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        return Sign(mechanism, keyHandle, inputStream, 4096);
    }

    /// <summary>
    /// Signs multi-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, string keyPin, Stream inputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign2b", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        return Sign(mechanism, keyHandle, keyPin, inputStream, 4096);
    }

    /// <summary>
    /// Signs multi-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] keyPin, Stream inputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign2c", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        return Sign(mechanism, keyHandle, keyPin, inputStream, 4096);
    }

    /// <summary>
    /// Signs multi-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <param name="performLogin">Flag indicating whether context specific login should be performed</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <returns>Signature</returns>
    protected byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, int bufferLength, bool performLogin, byte[] keyPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignInit", rv);

        if (performLogin)
        {
            byte[] pinValue = null;
            NativeCULong pinValueLen = (NativeCULong)0;
            if (keyPin != null)
            {
                pinValue = keyPin;
                pinValueLen = (NativeCULong)(keyPin.Length);
            }

            rv = _pkcs11Library.C_Login(_sessionId, CKU.CKU_CONTEXT_SPECIFIC, pinValue, pinValueLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Login", rv);
        }

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_SignUpdate(_sessionId, part, (NativeCULong)(bytesRead));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_SignUpdate", rv);
        }

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_SignFinal(_sessionId, null, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignFinal", rv);

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_SignFinal(_sessionId, signature, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignFinal", rv);

        if (signature.Length != (int)(signatureLen))
            Array.Resize(ref signature, (int)(signatureLen));

        return signature;
    }

    /// <summary>
    /// Signs multi-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign3a", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        return Sign(mechanism, keyHandle, inputStream, bufferLength, false, null);
    }

    /// <summary>
    /// Signs multi-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, string keyPin, Stream inputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign3b", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        return Sign(mechanism, keyHandle, inputStream, bufferLength, true, System.Text.Encoding.UTF8.GetBytes(keyPin));
    }

    /// <summary>
    /// Signs multi-part data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Signature</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] keyPin, Stream inputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Sign3c", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        return Sign(mechanism, keyHandle, inputStream, bufferLength, true, keyPin);
    }

    /// <summary>
    /// Signs single-part data, where the data can be recovered from the signature
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="data">Data to be signed</param>
    /// <param name="performLogin">Flag indicating whether context specific login should be performed</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <returns>Signature</returns>
    protected byte[] SignRecover(Mechanism mechanism, ObjectHandle keyHandle, byte[] data, bool performLogin, byte[] keyPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::SignRecover1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignRecoverInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignRecoverInit", rv);

        if (performLogin)
        {
            byte[] pinValue = null;
            NativeCULong pinValueLen = (NativeCULong)0;
            if (keyPin != null)
            {
                pinValue = keyPin;
                pinValueLen = (NativeCULong)(keyPin.Length);
            }

            rv = _pkcs11Library.C_Login(_sessionId, CKU.CKU_CONTEXT_SPECIFIC, pinValue, pinValueLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Login", rv);
        }

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_SignRecover(_sessionId, data, (NativeCULong)(data.Length), null, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignRecover", rv);

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_SignRecover(_sessionId, data, (NativeCULong)(data.Length), signature, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignRecover", rv);

        if (signature.Length != (int)(signatureLen))
            Array.Resize(ref signature, (int)(signatureLen));

        return signature;
    }

    /// <summary>
    /// Signs single-part data, where the data can be recovered from the signature
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="data">Data to be signed</param>
    /// <returns>Signature</returns>
    public byte[] SignRecover(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::SignRecover1a", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return SignRecover(mechanism, keyHandle, data, false, null);
    }

    /// <summary>
    /// Signs single-part data, where the data can be recovered from the signature
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="data">Data to be signed</param>
    /// <returns>Signature</returns>
    public byte[] SignRecover(Mechanism mechanism, ObjectHandle keyHandle, string keyPin, byte[] data)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::SignRecover1b", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return SignRecover(mechanism, keyHandle, data, true, System.Text.Encoding.UTF8.GetBytes(keyPin));
    }

    /// <summary>
    /// Signs single-part data, where the data can be recovered from the signature
    /// </summary>
    /// <param name="mechanism">Signature mechanism</param>
    /// <param name="keyHandle">Signature key</param>
    /// <param name="keyPin">Context specific signature pin</param>
    /// <param name="data">Data to be signed</param>
    /// <returns>Signature</returns>
    public byte[] SignRecover(Mechanism mechanism, ObjectHandle keyHandle, byte[] keyPin, byte[] data)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::SignRecover1c", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return SignRecover(mechanism, keyHandle, data, true, keyPin);
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="signature">Signature</param>
    /// <param name="encryptedData">Encrypted data</param>
    public void SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, byte[] data, out byte[] signature, out byte[] encryptedData)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt1a", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        using (MemoryStream inputMemoryStream = new MemoryStream(data), outputMemorySteam = new MemoryStream())
        {
            signature = SignEncrypt(signingMechanism, signingKeyHandle, encryptionMechanism, encryptionKeyHandle, inputMemoryStream, outputMemorySteam);
            encryptedData = outputMemorySteam.ToArray();
        }
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="signingKeyPin">Context specific signature pin</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="signature">Signature</param>
    /// <param name="encryptedData">Encrypted data</param>
    public void SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, string signingKeyPin, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, byte[] data, out byte[] signature, out byte[] encryptedData)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt1b", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        using (MemoryStream inputMemoryStream = new MemoryStream(data), outputMemorySteam = new MemoryStream())
        {
            signature = SignEncrypt(signingMechanism, signingKeyHandle, signingKeyPin, encryptionMechanism, encryptionKeyHandle, inputMemoryStream, outputMemorySteam);
            encryptedData = outputMemorySteam.ToArray();
        }
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="signingKeyPin">Context specific signature pin</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="signature">Signature</param>
    /// <param name="encryptedData">Encrypted data</param>
    public void SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, byte[] signingKeyPin, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, byte[] data, out byte[] signature, out byte[] encryptedData)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt1c", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        using (MemoryStream inputMemoryStream = new MemoryStream(data), outputMemorySteam = new MemoryStream())
        {
            signature = SignEncrypt(signingMechanism, signingKeyHandle, signingKeyPin, encryptionMechanism, encryptionKeyHandle, inputMemoryStream, outputMemorySteam);
            encryptedData = outputMemorySteam.ToArray();
        }
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <returns>Signature</returns>
    public byte[] SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, Stream inputStream, Stream outputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt2a", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        return SignEncrypt(signingMechanism, signingKeyHandle, encryptionMechanism, encryptionKeyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="signingKeyPin">Context specific signature pin</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <returns>Signature</returns>
    public byte[] SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, string signingKeyPin, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, Stream inputStream, Stream outputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt2b", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        return SignEncrypt(signingMechanism, signingKeyHandle, signingKeyPin, encryptionMechanism, encryptionKeyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="signingKeyPin">Context specific signature pin</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <returns>Signature</returns>
    public byte[] SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, byte[] signingKeyPin, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, Stream inputStream, Stream outputStream)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt2c", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        return SignEncrypt(signingMechanism, signingKeyHandle, signingKeyPin, encryptionMechanism, encryptionKeyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <param name="performLogin">Flag indicating whether context specific login should be performed</param>
    /// <param name="signingKeyPin">Context specific signature pin</param>
    /// <returns>Signature</returns>
    protected byte[] SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, Stream inputStream, Stream outputStream, int bufferLength, bool performLogin, byte[] signingKeyPin)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckSigningMechanism = (CK_MECHANISM)signingMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckSigningMechanism, (NativeCULong)(signingKeyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignInit", rv);

        if (performLogin)
        {
            byte[] pinValue = null;
            NativeCULong pinValueLen = (NativeCULong)0;
            if (signingKeyPin != null)
            {
                pinValue = signingKeyPin;
                pinValueLen = (NativeCULong)(signingKeyPin.Length);
            }

            rv = _pkcs11Library.C_Login(_sessionId, CKU.CKU_CONTEXT_SPECIFIC, pinValue, pinValueLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Login", rv);
        }

        CK_MECHANISM ckEncryptionMechanism = (CK_MECHANISM)encryptionMechanism.ToMarshalableStructure();

        rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckEncryptionMechanism, (NativeCULong)(encryptionKeyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_EncryptInit", rv);

        byte[] part = new byte[bufferLength];
        byte[] encryptedPart = new byte[bufferLength];
        NativeCULong encryptedPartLen = (NativeCULong)(encryptedPart.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            encryptedPartLen = (NativeCULong)(encryptedPart.Length);
            rv = _pkcs11Library.C_SignEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                throw new Pkcs11Exception("C_SignEncryptUpdate", rv);

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                encryptedPart = new byte[(int)encryptedPartLen];

                rv = _pkcs11Library.C_SignEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_SignEncryptUpdate", rv);
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

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_SignFinal(_sessionId, null, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignFinal", rv);

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_SignFinal(_sessionId, signature, ref signatureLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_SignFinal", rv);

        if (signature.Length != (int)(signatureLen))
            Array.Resize(ref signature, (int)(signatureLen));

        return signature;
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Signature</returns>
    public byte[] SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt3a", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        return SignEncrypt(signingMechanism, signingKeyHandle, encryptionMechanism, encryptionKeyHandle, inputStream, outputStream, bufferLength, false, null);
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="signingKeyPin">Context specific signature pin</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Signature</returns>
    public byte[] SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, string signingKeyPin, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt3b", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        return SignEncrypt(signingMechanism, signingKeyHandle, encryptionMechanism, encryptionKeyHandle, inputStream, outputStream, bufferLength, true, System.Text.Encoding.UTF8.GetBytes(signingKeyPin));
    }

    /// <summary>
    /// Signs and encrypts data
    /// </summary>
    /// <param name="signingMechanism">Signing mechanism</param>
    /// <param name="signingKeyHandle">Handle of the signing key</param>
    /// <param name="signingKeyPin">Context specific signature pin</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="encryptionKeyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Signature</returns>
    public byte[] SignEncrypt(Mechanism signingMechanism, ObjectHandle signingKeyHandle, byte[] signingKeyPin, Mechanism encryptionMechanism, ObjectHandle encryptionKeyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.Debug("Session({0})::SignEncrypt3c", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        return SignEncrypt(signingMechanism, signingKeyHandle, encryptionMechanism, encryptionKeyHandle, inputStream, outputStream, bufferLength, true, signingKeyPin);
    }
}
