using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

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

        _logger.LogDebug("Session({SessionId})::Sign1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_SignInit");

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
            Pkcs11Exception.ThrowIfError(rv, "C_Login");
        }

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_Sign(_sessionId, data, (NativeCULong)(data.Length), null, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Sign");

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_Sign(_sessionId, data, (NativeCULong)(data.Length), signature, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_Sign");

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
        using var _ = AcquireExclusive();
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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign1a", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return Sign(mechanism, keyHandle, data, false, null);
    }

    /// <summary>String-keyPin variant — see <see cref="Sign(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>.</summary>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, string keyPin, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign1b", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        return Sign(mechanism, keyHandle, data, true, System.Text.Encoding.UTF8.GetBytes(keyPin));
    }

    /// <summary>byte[]-keyPin variant — see <see cref="Sign(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>.</summary>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, byte[] keyPin, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign1c", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign2a", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign2b", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign2c", _sessionId);

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

        _logger.LogDebug("Session({SessionId})::Sign3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_SignInit");

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
            Pkcs11Exception.ThrowIfError(rv, "C_Login");
        }

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_SignUpdate(_sessionId, part, (NativeCULong)(bytesRead));
            Pkcs11Exception.ThrowIfError(rv, "C_SignUpdate");
        }

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_SignFinal(_sessionId, null, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_SignFinal");

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_SignFinal(_sessionId, signature, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_SignFinal");

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign3a", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign3b", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::Sign3c", _sessionId);

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

        _logger.LogDebug("Session({SessionId})::SignRecover1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignRecoverInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_SignRecoverInit");

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
            Pkcs11Exception.ThrowIfError(rv, "C_Login");
        }

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_SignRecover(_sessionId, data, (NativeCULong)(data.Length), null, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_SignRecover");

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_SignRecover(_sessionId, data, (NativeCULong)(data.Length), signature, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_SignRecover");

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::SignRecover1a", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::SignRecover1b", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        _logger.LogDebug("Session({SessionId})::SignRecover1c", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt1a", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt1b", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt1c", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt2a", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt2b", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt2c", _sessionId);

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

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        GuardMechanism((CKM)signingMechanism.Type);
        GuardMechanism((CKM)encryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::SignEncrypt3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckSigningMechanism = (CK_MECHANISM)signingMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_SignInit(_sessionId, ref ckSigningMechanism, (NativeCULong)(signingKeyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_SignInit");

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
            Pkcs11Exception.ThrowIfError(rv, "C_Login");
        }

        CK_MECHANISM ckEncryptionMechanism = (CK_MECHANISM)encryptionMechanism.ToMarshalableStructure();

        rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckEncryptionMechanism, (NativeCULong)(encryptionKeyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptInit");

        byte[] part = new byte[bufferLength];
        byte[] encryptedPart = new byte[bufferLength];
        NativeCULong encryptedPartLen = (NativeCULong)(encryptedPart.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            encryptedPartLen = (NativeCULong)(encryptedPart.Length);
            rv = _pkcs11Library.C_SignEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
            // C_SignEncryptUpdate may signal CKR_BUFFER_TOO_SMALL; allocate and retry once.
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_SignEncryptUpdate");

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                encryptedPart = new byte[(int)encryptedPartLen];

                rv = _pkcs11Library.C_SignEncryptUpdate(_sessionId, part, (NativeCULong)(bytesRead), encryptedPart, ref encryptedPartLen);
                Pkcs11Exception.ThrowIfError(rv, "C_SignEncryptUpdate");
            }

            outputStream.Write(encryptedPart, 0, (int)(encryptedPartLen));
        }

        byte[] lastEncryptedPart = null;
        NativeCULong lastEncryptedPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, null, ref lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");

        lastEncryptedPart = new byte[(int)lastEncryptedPartLen];
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, ref lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_EncryptFinal");

        if (lastEncryptedPartLen > (NativeCULong)0)
            outputStream.Write(lastEncryptedPart, 0, (int)(lastEncryptedPartLen));

        NativeCULong signatureLen = (NativeCULong)0;
        rv = _pkcs11Library.C_SignFinal(_sessionId, null, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_SignFinal");

        byte[] signature = new byte[(int)signatureLen];
        rv = _pkcs11Library.C_SignFinal(_sessionId, signature, ref signatureLen);
        Pkcs11Exception.ThrowIfError(rv, "C_SignFinal");

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt3a", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt3b", _sessionId);

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
        using var _ = AcquireExclusive();
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (signingMechanism == null)
            throw new ArgumentNullException("signingMechanism");

        if (signingKeyHandle == null)
            throw new ArgumentNullException("signingKeyHandle");

        if (encryptionMechanism == null)
            throw new ArgumentNullException("encryptionMechanism");

        if (encryptionKeyHandle == null)
            throw new ArgumentNullException("encryptionKeyHandle");

        _logger.LogDebug("Session({SessionId})::SignEncrypt3c", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        return SignEncrypt(signingMechanism, signingKeyHandle, encryptionMechanism, encryptionKeyHandle, inputStream, outputStream, bufferLength, true, signingKeyPin);
    }

    // === Secure-default signing helpers ====================================

    /// <summary>
    /// Signs <paramref name="data"/> using RSA-PSS with SHA-256, MGF1+SHA-256, and a 32-byte salt
    /// (matching the hash output length per RFC 8017).
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an RSA private key (CKA_SIGN=true).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (length = RSA modulus / 8).</returns>
    public byte[] SignRsaPss(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var p = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, p);
        return Sign(mechanism, privateKeyHandle, data);
    }

    /// <summary>
    /// Signs <paramref name="data"/> using ECDSA with SHA-256 — the standard modern ECDSA mode.
    /// Output is the raw concatenated (r || s) form per PKCS#11 §2.3.6.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an EC private key on a strong curve (P-256+, secp256k1, P-384, P-521).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (2 × curve coordinate length; 64 bytes for P-256).</returns>
    public byte[] SignEcdsa(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
        return Sign(mechanism, privateKeyHandle, data);
    }

    /// <summary>
    /// Signs <paramref name="data"/> using Ed25519 (EdDSA over Curve25519).
    /// Output is a fixed 64-byte signature.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an Ed25519 private key (CKK_EC_EDWARDS, CKA_EC_PARAMS=Ed25519 OID).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>64-byte Ed25519 signature.</returns>
    public byte[] SignEd25519(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        return Sign(mechanism, privateKeyHandle, data);
    }

    /// <summary>
    /// Signs <paramref name="data"/> using Ed448 (EdDSA over Curve448).
    /// Output is a fixed 114-byte signature.
    /// </summary>
    /// <param name="privateKeyHandle">Handle of an Ed448 private key (CKK_EC_EDWARDS, CKA_EC_PARAMS=Ed448 OID).</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>114-byte Ed448 signature.</returns>
    public byte[] SignEd448(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        return Sign(mechanism, privateKeyHandle, data);
    }

    // === Legacy named shortcut (gated, compile-time warning) ===============

    /// <summary>
    /// Signs using RSA PKCS#1 v1.5 padding. **Use <see cref="SignRsaPss"/> instead.**
    /// This method exists for compatibility; it throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 signing is vulnerable to fault attacks and is not recommended for new code. " +
              "Use SignRsaPss instead. If you must use it, set Session.AllowInsecure = true.")]
    public byte[] SignRsaPkcs1V15(ObjectHandle privateKeyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        return Sign(mechanism, privateKeyHandle, data);
    }
}
