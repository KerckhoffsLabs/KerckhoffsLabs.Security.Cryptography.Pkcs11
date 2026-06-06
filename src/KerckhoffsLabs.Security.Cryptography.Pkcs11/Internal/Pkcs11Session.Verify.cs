using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11Session
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
        using var _ = AcquireExclusive();
        ArgumentNullException.ThrowIfNull(mechanism);
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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify1");

        ArgumentNullException.ThrowIfNull(data);

        ArgumentNullException.ThrowIfNull(signature);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_VerifyInit");

        rv = _pkcs11Library.C_Verify(_sessionId, data, (NativeCULong)(data.Length), signature, (NativeCULong)(signature.Length));
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw Pkcs11Exception.Create(rv, "C_Verify");
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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", nameof(bufferLength));

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_VerifyInit");

        bool finalized = false;
        try
        {
            byte[] part = new byte[bufferLength];
            int bytesRead = 0;

            while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
            {
                rv = _pkcs11Library.C_VerifyUpdate(_sessionId, part, (NativeCULong)(bytesRead));
                Pkcs11Exception.ThrowIfError(rv, "C_VerifyUpdate");
            }

            rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature, (NativeCULong)(signature.Length));
            // C_VerifyFinal always finalizes — whether the signature was valid, invalid, or
            // the call failed with any other CKR — the verify operation is consumed.
            finalized = true;
            if (rv == CKR.CKR_OK)
                isValid = true;
            else if (rv == CKR.CKR_SIGNATURE_INVALID)
                isValid = false;
            else
                throw Pkcs11Exception.Create(rv, "C_VerifyFinal");
        }
        finally
        {
            if (!finalized)
                TryCancelOperation(CKF.CKF_VERIFY, "Verify");
        }
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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(mechanism);


        GuardMechanism((CKM)mechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifyRecover");

        ArgumentNullException.ThrowIfNull(signature);

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyRecoverInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_VerifyRecoverInit");

        NativeCULong dataLen = (NativeCULong)0;
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, (NativeCULong)(signature.Length), null, ref dataLen);
        Pkcs11Exception.ThrowIfError(rv, "C_VerifyRecover");

        byte[] data = new byte[(int)dataLen];
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, (NativeCULong)(signature.Length), data, ref dataLen);
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw Pkcs11Exception.Create(rv, "C_VerifyRecover");

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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism((CKM)verificationMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify1");

        ArgumentNullException.ThrowIfNull(data);

        ArgumentNullException.ThrowIfNull(signature);

        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new();
        DecryptVerify(verificationMechanism, verificationKeyHandle, decryptionMechanism, decryptionKeyHandle, inputMemoryStream, outputMemorySteam, signature, out isValid);
        decryptedData = outputMemorySteam.ToArray();
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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism((CKM)verificationMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism((CKM)verificationMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", nameof(bufferLength));

        CK_MECHANISM ckVerificationMechanism = (CK_MECHANISM)verificationMechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckVerificationMechanism, (NativeCULong)(verificationKeyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_VerifyInit");

        CK_MECHANISM ckDecryptionMechanism = (CK_MECHANISM)decryptionMechanism.ToMarshalableStructure();

        rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckDecryptionMechanism, (NativeCULong)(decryptionKeyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptInit");

        byte[] encryptedPart = new byte[bufferLength];
        byte[] part = new byte[bufferLength];
        NativeCULong partLen = (NativeCULong)(part.Length);

        int bytesRead = 0;
        while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
        {
            partLen = (NativeCULong)(part.Length);
            rv = _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
            if (rv is not CKR.CKR_OK and not CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_DecryptVerifyUpdate");

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                part = new byte[(int)partLen];

                rv = _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                Pkcs11Exception.ThrowIfError(rv, "C_DecryptVerifyUpdate");
            }

            outputStream.Write(part, 0, (int)(partLen));
        }

        byte[]? lastPart = null;
        NativeCULong lastPartLen = (NativeCULong)0;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, null, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");

        lastPart = new byte[(int)lastPartLen];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, ref lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, "C_DecryptFinal");

        if (lastPartLen > (NativeCULong)0)
            outputStream.Write(lastPart, 0, (int)(lastPartLen));

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature, (NativeCULong)(signature.Length));
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw Pkcs11Exception.Create(rv, "C_VerifyFinal");
    }

    // === Secure-default verification helpers ===============================

    /// <summary>Verifies an Ed25519 signature.</summary>
    /// <param name="publicKeyHandle">Handle of an Ed25519 public key.</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">64-byte Ed25519 signature to verify.</param>
    /// <param name="isValid">Set to true if the signature verifies; false otherwise.</param>
    public void VerifyEd25519(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }

    /// <summary>Verifies an Ed448 signature.</summary>
    /// <param name="publicKeyHandle">Handle of an Ed448 public key.</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">114-byte Ed448 signature to verify.</param>
    /// <param name="isValid">Set to true if the signature verifies; false otherwise.</param>
    public void VerifyEd448(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_EDDSA);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }

}
