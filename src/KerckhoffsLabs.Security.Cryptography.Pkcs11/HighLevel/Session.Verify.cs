using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

public partial class Session
{
    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the given
    /// mechanism and key. Throws <see cref="InsecureOperationException"/> if
    /// <paramref name="mechanism"/> is insecure-by-default and <see cref="AllowInsecure"/> is false.
    /// </summary>
    /// <param name="mechanism">Verification mechanism.</param>
    /// <param name="keyHandle">Handle of the public/MAC key.</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">Signature bytes to verify.</param>
    /// <param name="isValid">Set to true if the signature verifies; false otherwise.</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(keyHandle);
        byte[] dataBuf = data.ToArray();
        byte[] sigBuf = signature.ToArray();
        Verify(mechanism, keyHandle, dataBuf, sigBuf, out isValid);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="data">Data that was signed</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, byte[] data, byte[] signature, out bool isValid)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Verify1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        if (signature == null)
            throw new ArgumentNullException("signature");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_VerifyInit", rv);

        rv = _pkcs11Library.C_Verify(_sessionId, data, (NativeCULong)(data.Length), signature, (NativeCULong)(signature.Length));
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw new Pkcs11Exception("C_Verify", rv);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="inputStream">Input stream from which data that was signed should be read</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, byte[] signature, out bool isValid)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Verify2", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (signature == null)
            throw new ArgumentNullException("signature");

        Verify(mechanism, keyHandle, inputStream, signature, out isValid, 4096);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="inputStream">Input stream from which data that was signed should be read</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void Verify(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, byte[] signature, out bool isValid, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::Verify3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (signature == null)
            throw new ArgumentNullException("signature");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_VerifyInit", rv);

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifyUpdate(_sessionId, part, (NativeCULong)(bytesRead));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_VerifyUpdate", rv);
        }

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature, (NativeCULong)(signature.Length));
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw new Pkcs11Exception("C_VerifyFinal", rv);
    }

    /// <summary>
    /// Verifies signature of data, where the data can be recovered from the signature
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    /// <returns>Data recovered from the signature</returns>
    public byte[] VerifyRecover(Mechanism mechanism, ObjectHandle keyHandle, byte[] signature, out bool isValid)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (mechanism == null)
            throw new ArgumentNullException("mechanism");

        if (keyHandle == null)
            throw new ArgumentNullException("keyHandle");

        GuardMechanism((CKM)mechanism.Type);

        _logger.Debug("Session({0})::VerifyRecover", _sessionId);

        if (signature == null)
            throw new ArgumentNullException("signature");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyRecoverInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_VerifyRecoverInit", rv);

        NativeCULong dataLen = (NativeCULong)0;
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, (NativeCULong)(signature.Length), null, ref dataLen);
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_VerifyRecover", rv);

        byte[] data = new byte[(int)dataLen];
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, (NativeCULong)(signature.Length), data, ref dataLen);
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw new Pkcs11Exception("C_VerifyRecover", rv);

        if (data.Length != (int)(dataLen))
            Array.Resize(ref data, (int)(dataLen));

        return data;
    }

    /// <summary>
    /// Decrypts data and verifies a signature of data
    /// </summary>
    /// <param name="verificationMechanism">Verification mechanism</param>
    /// <param name="verificationKeyHandle">Handle of the verification key</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="decryptionKeyHandle">Handle of the decryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="signature">Signature</param>
    /// <param name="decryptedData">Decrypted data</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, byte[] data, byte[] signature, out byte[] decryptedData, out bool isValid)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (verificationMechanism == null)
            throw new ArgumentNullException("verificationMechanism");

        if (decryptionMechanism == null)
            throw new ArgumentNullException("decryptionMechanism");

        if (verificationKeyHandle == null)
            throw new ArgumentNullException("verificationKeyHandle");

        if (decryptionKeyHandle == null)
            throw new ArgumentNullException("decryptionKeyHandle");

        GuardMechanism((CKM)verificationMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        _logger.Debug("Session({0})::DecryptVerify1", _sessionId);

        if (data == null)
            throw new ArgumentNullException("data");

        if (signature == null)
            throw new ArgumentNullException("signature");

        using (MemoryStream inputMemoryStream = new MemoryStream(data), outputMemorySteam = new MemoryStream())
        {
            DecryptVerify(verificationMechanism, verificationKeyHandle, decryptionMechanism, decryptionKeyHandle, inputMemoryStream, outputMemorySteam, signature, out isValid);
            decryptedData = outputMemorySteam.ToArray();
        }
    }

    /// <summary>
    /// Decrypts data and verifies a signature of data
    /// </summary>
    /// <param name="verificationMechanism">Verification mechanism</param>
    /// <param name="verificationKeyHandle">Handle of the verification key</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="decryptionKeyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    public void DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, Stream inputStream, Stream outputStream, byte[] signature, out bool isValid)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (verificationMechanism == null)
            throw new ArgumentNullException("verificationMechanism");

        if (decryptionMechanism == null)
            throw new ArgumentNullException("decryptionMechanism");

        if (verificationKeyHandle == null)
            throw new ArgumentNullException("verificationKeyHandle");

        if (decryptionKeyHandle == null)
            throw new ArgumentNullException("decryptionKeyHandle");

        GuardMechanism((CKM)verificationMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        _logger.Debug("Session({0})::DecryptVerify2", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (signature == null)
            throw new ArgumentNullException("signature");

        DecryptVerify(verificationMechanism, verificationKeyHandle, decryptionMechanism, decryptionKeyHandle, inputStream, outputStream, signature, out isValid, 4096);
    }

    /// <summary>
    /// Decrypts data and verifies a signature of data
    /// </summary>
    /// <param name="verificationMechanism">Verification mechanism</param>
    /// <param name="verificationKeyHandle">Handle of the verification key</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="decryptionKeyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="signature">Signature</param>
    /// <param name="isValid">Flag indicating whether signature is valid</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    public void DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, Stream inputStream, Stream outputStream, byte[] signature, out bool isValid, int bufferLength)
    {
        if (_disposed)
            throw new ObjectDisposedException(GetType().FullName);

        if (verificationMechanism == null)
            throw new ArgumentNullException("verificationMechanism");

        if (decryptionMechanism == null)
            throw new ArgumentNullException("decryptionMechanism");

        if (verificationKeyHandle == null)
            throw new ArgumentNullException("verificationKeyHandle");

        if (decryptionKeyHandle == null)
            throw new ArgumentNullException("decryptionKeyHandle");

        GuardMechanism((CKM)verificationMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        _logger.Debug("Session({0})::DecryptVerify3", _sessionId);

        if (inputStream == null)
            throw new ArgumentNullException("inputStream");

        if (outputStream == null)
            throw new ArgumentNullException("outputStream");

        if (signature == null)
            throw new ArgumentNullException("signature");

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckVerificationMechanism = (CK_MECHANISM)verificationMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckVerificationMechanism, (NativeCULong)(verificationKeyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_VerifyInit", rv);

        CK_MECHANISM ckDecryptionMechanism = (CK_MECHANISM)decryptionMechanism.ToMarshalableStructure();

        rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckDecryptionMechanism, (NativeCULong)(decryptionKeyHandle.ObjectId));
        if (rv != CKR.CKR_OK)
            throw new Pkcs11Exception("C_DecryptInit", rv);

        byte[] encryptedPart = new byte[bufferLength];
        byte[] part = new byte[bufferLength];
        NativeCULong partLen = (NativeCULong)(part.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
        {
            partLen = (NativeCULong)(part.Length);
            rv = _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                throw new Pkcs11Exception("C_DecryptVerifyUpdate", rv);

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                part = new byte[(int)partLen];

                rv = _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_DecryptVerifyUpdate", rv);
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

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature, (NativeCULong)(signature.Length));
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw new Pkcs11Exception("C_VerifyFinal", rv);
    }
}
