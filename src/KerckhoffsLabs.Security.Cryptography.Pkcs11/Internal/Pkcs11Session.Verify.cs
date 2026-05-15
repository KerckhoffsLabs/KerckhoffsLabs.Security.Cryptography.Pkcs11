using KerckhoffsLabs.Security.Cryptography.Pkcs11;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Logging;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using Microsoft.Extensions.Logging;

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

        _logger.LogDebug("Session({SessionId})::Verify1", _sessionId);

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

        _logger.LogDebug("Session({SessionId})::Verify2", _sessionId);

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

        _logger.LogDebug("Session({SessionId})::Verify3", _sessionId);

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

        CK_MECHANISM ckMechanism = (CK_MECHANISM)mechanism.ToMarshalableStructure();

        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, "C_VerifyInit");

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifyUpdate(_sessionId, part, (NativeCULong)(bytesRead));
            Pkcs11Exception.ThrowIfError(rv, "C_VerifyUpdate");
        }

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature, (NativeCULong)(signature.Length));
        if (rv == CKR.CKR_OK)
            isValid = true;
        else if (rv == CKR.CKR_SIGNATURE_INVALID)
            isValid = false;
        else
            throw Pkcs11Exception.Create(rv, "C_VerifyFinal");
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

        _logger.LogDebug("Session({SessionId})::VerifyRecover", _sessionId);

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

        _logger.LogDebug("Session({SessionId})::DecryptVerify1", _sessionId);

        ArgumentNullException.ThrowIfNull(data);

        ArgumentNullException.ThrowIfNull(signature);

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
        using var _ = AcquireExclusive();
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        GuardMechanism((CKM)verificationMechanism.Type);
        GuardMechanism((CKM)decryptionMechanism.Type);

        _logger.LogDebug("Session({SessionId})::DecryptVerify2", _sessionId);

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

        _logger.LogDebug("Session({SessionId})::DecryptVerify3", _sessionId);

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException("Value has to be positive number", "bufferLength");

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
            if (rv != CKR.CKR_OK && rv != CKR.CKR_BUFFER_TOO_SMALL)
                Pkcs11Exception.ThrowIfError(rv, "C_DecryptVerifyUpdate");

            if (rv == CKR.CKR_BUFFER_TOO_SMALL)
            {
                part = new byte[(int)partLen];

                rv = _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, encryptedPart, (NativeCULong)(bytesRead), part, ref partLen);
                Pkcs11Exception.ThrowIfError(rv, "C_DecryptVerifyUpdate");
            }

            outputStream.Write(part, 0, (int)(partLen));
        }

        byte[] lastPart = null;
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

    /// <summary>Verifies <paramref name="signature"/> over <paramref name="data"/> using RSA-PSS / SHA-256 / MGF1+SHA-256 / 32-byte salt.</summary>
    /// <param name="publicKeyHandle">Handle of an RSA public key (CKA_VERIFY=true).</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">Signature bytes to verify.</param>
    /// <param name="isValid">Set to true if the signature verifies; false otherwise.</param>
    public void VerifyRsaPss(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        using var p = new CkmRsaPkcsPssParams(CKM.CKM_SHA256, CKG.CKG_MGF1_SHA256, saltLength: 32);
        using var mechanism = new Mechanism(CKM.CKM_SHA256_RSA_PKCS_PSS, p);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }

    /// <summary>Verifies an ECDSA-SHA256 signature.</summary>
    /// <param name="publicKeyHandle">Handle of an EC public key (CKA_VERIFY=true).</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">Signature bytes to verify.</param>
    /// <param name="isValid">Set to true if the signature verifies; false otherwise.</param>
    public void VerifyEcdsa(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        if (SupportsMechanism(CKM.CKM_ECDSA_SHA256))
        {
            using var mechanism = new Mechanism(CKM.CKM_ECDSA_SHA256);
            Verify(mechanism, publicKeyHandle, data, signature, out isValid);
            return;
        }
        // Fallback: pre-hash in managed code and use raw CKM_ECDSA.
        byte[] hash = System.Security.Cryptography.SHA256.HashData(data);
        using var rawMechanism = new Mechanism(CKM.CKM_ECDSA);
        Verify(rawMechanism, publicKeyHandle, hash, signature, out isValid);
    }

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

    // === Legacy named shortcut (gated, compile-time warning) ===============

    /// <summary>
    /// Verifies a signature produced with RSA PKCS#1 v1.5 padding.
    /// **Use <see cref="VerifyRsaPss"/> instead.** Throws <see cref="InsecureOperationException"/>
    /// at runtime unless <see cref="AllowInsecure"/> is set on the session.
    /// </summary>
    [Obsolete("RSA PKCS#1 v1.5 signatures are vulnerable to fault attacks and are not recommended for new code. " +
              "Use VerifyRsaPss instead. If you must use it, set Session.AllowInsecure = true.")]
    public void VerifyRsaPkcs1V15(ObjectHandle publicKeyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, out bool isValid)
    {
        using var _ = AcquireExclusive();
        using var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);
        Verify(mechanism, publicKeyHandle, data, signature, out isValid);
    }
}
