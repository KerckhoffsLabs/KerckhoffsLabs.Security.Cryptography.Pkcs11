using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// Signs <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">Signing mechanism.</param>
    /// <param name="keyHandle">Handle of the private/MAC key.</param>
    /// <param name="data">Data to sign.</param>
    /// <returns>Signature bytes (size depends on key + mechanism).</returns>
    public byte[] Sign(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        Enforce(mechanism, CryptoOperation.Sign);
        return SignAfterPolicyCheck(mechanism, keyHandle, data);
    }

    /// <summary>
    /// Signs a digest the caller computed with RSASSA-PKCS1-v1_5: raw <c>CKM_RSA_PKCS</c> over the
    /// DigestInfo this method encodes, which the policy judges as the combined mechanism for
    /// <paramref name="hash"/> (<c>CKM_SHA256_RSA_PKCS</c> for SHA-256), the scheme the operation is.
    /// Raw <c>CKM_RSA_PKCS</c> keeps its own verdict through <see cref="Sign"/>, which signs any input.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The policy refuses the combined mechanism for signing.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hash"/> is not supported.</exception>
    /// <exception cref="CryptographicException"><paramref name="digest"/> is not the length of a <paramref name="hash"/> digest.</exception>
    internal byte[] SignPkcs1Digest(HashAlgorithmName hash, ObjectHandle keyHandle, ReadOnlySpan<byte> digest)
    {
        using var _ = AcquireExclusive();

        (CKM scheme, byte[] digestInfo) = Pkcs1DigestInfo.Encode(hash, digest);
        Enforce(new Mechanism(scheme), CryptoOperation.Sign);
        return SignAfterPolicyCheck(RawRsaPkcs1(), keyHandle, digestInfo);
    }

    // KLPKCS11008 warns a caller who selects CKM_RSA_PKCS, for its PKCS#1 v1.5 encryption. The two methods
    // above sign and verify only the DigestInfo they encode, under the verdict on the combined signature
    // scheme, so this is the one place the library names it for that.
#pragma warning disable KLPKCS11008
    private static Mechanism RawRsaPkcs1() => new(CKM.CKM_RSA_PKCS);
#pragma warning restore KLPKCS11008

    private byte[] SignAfterPolicyCheck(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        Log.SessionTrace(_logger, (ulong)_sessionId, "Sign");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Sign");
        CKR rv = _pkcs11Library.C_SignInit(_sessionId, in ckMechanism, (NativeCULong)keyHandle.ObjectId);
        operation.Begin(CKF.CKF_SIGN, rv, OpSignInit);

        byte[] signature = CallWithLengthProbe(data,
            (ReadOnlySpan<byte> input, Span<byte> buf, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_Sign(_sessionId, input, buf, lengthOnly, out len),
            OpSign,
            KnownOutputLength.OfSignature(mechanism.Type),
            () => _pkcs11Library.C_SignInit(_sessionId, in ckMechanism, (NativeCULong)keyHandle.ObjectId));
        operation.Completed();

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return signature;
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="data"/> using the given
    /// mechanism and key. Throws <see cref="CryptoPolicyViolationException"/> if
    /// <paramref name="mechanism"/> is insecure-by-default and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">Verification mechanism.</param>
    /// <param name="keyHandle">Handle of the public/MAC key.</param>
    /// <param name="data">Data the signature was computed over.</param>
    /// <param name="signature">Signature bytes to verify.</param>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool Verify(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        Enforce(mechanism, CryptoOperation.Verify);
        return VerifyAfterPolicyCheck(mechanism, keyHandle, data, signature);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="data">Data that was signed</param>
    /// <param name="signature">Signature</param>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool Verify(Mechanism mechanism, ObjectHandle keyHandle, byte[] data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        return Verify(mechanism, keyHandle, data.AsSpan(), signature.AsSpan());
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="inputStream">Input stream from which data that was signed should be read</param>
    /// <param name="signature">Signature</param>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool Verify(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, byte[] signature)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

        return Verify(mechanism, keyHandle, inputStream, signature, 4096);
    }

    /// <summary>
    /// Verifies a signature of data, where the signature is an appendix to the data
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="inputStream">Input stream from which data that was signed should be read</param>
    /// <param name="signature">Signature</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool Verify(Mechanism mechanism, ObjectHandle keyHandle, Stream inputStream, byte[] signature, int bufferLength)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Verify");
        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, in ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifyInit);

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_VerifyUpdate(_sessionId, part.AsSpan(0, bytesRead));
            Pkcs11Exception.ThrowIfError(rv, OpVerifyUpdate);
        }

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature);
        operation.CompletedIfVerdict(rv);
        bool isValid = IsVerified(rv, OpVerifyFinal, mechanism.Type, signature.Length);

        mechanism.AbsorbOutput(mechParams);
        return isValid;
    }

    /// <summary>
    /// Verifies an RSASSA-PKCS1-v1_5 signature over a digest the caller computed, judged as
    /// <see cref="SignPkcs1Digest"/> signs: raw <c>CKM_RSA_PKCS</c> over the DigestInfo this method
    /// encodes, under the policy's verdict on the combined mechanism for <paramref name="hash"/>.
    /// </summary>
    /// <exception cref="CryptoPolicyViolationException">The policy refuses the combined mechanism for verification.</exception>
    /// <exception cref="NotSupportedException"><paramref name="hash"/> is not supported.</exception>
    /// <exception cref="CryptographicException"><paramref name="digest"/> is not the length of a <paramref name="hash"/> digest.</exception>
    internal bool VerifyPkcs1Digest(HashAlgorithmName hash, ObjectHandle keyHandle, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        using var _ = AcquireExclusive();

        (CKM scheme, byte[] digestInfo) = Pkcs1DigestInfo.Encode(hash, digest);
        Enforce(new Mechanism(scheme), CryptoOperation.Verify);
        return VerifyAfterPolicyCheck(RawRsaPkcs1(), keyHandle, digestInfo, signature);
    }

    private bool VerifyAfterPolicyCheck(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        Log.SessionTrace(_logger, (ulong)_sessionId, "Verify1");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Verify");
        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, in ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifyInit);

        rv = _pkcs11Library.C_Verify(_sessionId, data, signature);
        operation.CompletedIfVerdict(rv);
        bool isValid = IsVerified(rv, OpVerify, mechanism.Type, signature.Length);

        mechanism.AbsorbOutput(mechParams);
        return isValid;
    }

    /// <summary>
    /// Verifies signature of data, where the data can be recovered from the signature
    /// </summary>
    /// <param name="mechanism">Verification mechanism;</param>
    /// <param name="keyHandle">Verification key</param>
    /// <param name="signature">Signature</param>
    /// <param name="data">Data recovered from the signature; empty when it does not verify.</param>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool VerifyRecover(Mechanism mechanism, ObjectHandle keyHandle, byte[] signature, out byte[] data)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Verify);

        Log.SessionTrace(_logger, (ulong)_sessionId, "VerifyRecover");

        ArgumentNullException.ThrowIfNull(signature);

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("VerifyRecover");
        CKR rv = _pkcs11Library.C_VerifyRecoverInit(_sessionId, in ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY_RECOVER, rv, OpVerifyRecoverInit);

        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, default, lengthOnly: true, out NativeCULong dataLen);
        Pkcs11Exception.ThrowIfError(rv, OpVerifyRecover);

        byte[] recovered = new byte[ReportedLength.ForAllocation(dataLen, OpVerifyRecover)];
        rv = _pkcs11Library.C_VerifyRecover(_sessionId, signature, recovered, lengthOnly: false, out dataLen);
        operation.CompletedIfVerdict(rv);
        bool isValid = IsVerified(rv, OpVerifyRecover);

        mechanism.AbsorbOutput(mechParams);

        if (!isValid)
        {
            // Nothing was recovered, and the reported length is not one to trust.
            CryptographicOperations.ZeroMemory(recovered);
            data = [];
            return false;
        }
        data = ReportedLength.Trim(recovered, dataLen, OpVerifyRecover);
        return true;
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
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, byte[] data, byte[] signature, out byte[] decryptedData)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(verificationMechanism, CryptoOperation.Verify);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify1");

        ArgumentNullException.ThrowIfNull(data);

        ArgumentNullException.ThrowIfNull(signature);

        // As in DecryptDigest: one buffer, sized to the ciphertext, zeroized on the way out.
        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new(data.Length);
        try
        {
            bool isValid = DecryptVerify(verificationMechanism, verificationKeyHandle, decryptionMechanism, decryptionKeyHandle, inputMemoryStream, outputMemorySteam, signature);
            decryptedData = outputMemorySteam.ToArray();
            return isValid;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(outputMemorySteam.GetBuffer());
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
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, Stream inputStream, Stream outputStream, byte[] signature)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(verificationMechanism, CryptoOperation.Verify);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        ThrowIfOneDescriptorDrivesBothHalves(verificationMechanism, decryptionMechanism, nameof(decryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

        return DecryptVerify(verificationMechanism, verificationKeyHandle, decryptionMechanism, decryptionKeyHandle, inputStream, outputStream, signature, 4096);
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
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns><see langword="true"/> if the signature verifies; <see langword="false"/> otherwise.</returns>
    public bool DecryptVerify(Mechanism verificationMechanism, ObjectHandle verificationKeyHandle, Mechanism decryptionMechanism, ObjectHandle decryptionKeyHandle, Stream inputStream, Stream outputStream, byte[] signature, int bufferLength)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(verificationMechanism);


        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(verificationMechanism, CryptoOperation.Verify);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptVerify3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        ArgumentNullException.ThrowIfNull(signature);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        // Both mechanisms marshal into the same scope: the two operations run interleaved, so both
        // parameter blocks have to stay alive until the last native call returns.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckVerificationMechanism = verificationMechanism.Marshal(scope, out Pkcs11ParameterBlock? verifyParams);

        using var operation = BeginOperation("DecryptVerify");
        CKR rv = _pkcs11Library.C_VerifyInit(_sessionId, in ckVerificationMechanism, (NativeCULong)(verificationKeyHandle.ObjectId));
        operation.Begin(CKF.CKF_VERIFY, rv, OpVerifyInit);

        CK_MECHANISM ckDecryptionMechanism = decryptionMechanism.Marshal(scope, out Pkcs11ParameterBlock? decryptParams);

        rv = _pkcs11Library.C_DecryptInit(_sessionId, in ckDecryptionMechanism, (NativeCULong)(decryptionKeyHandle.ObjectId));
        operation.Begin(CKF.CKF_DECRYPT, rv, OpDecryptInit);

        PumpStreamThrough(inputStream, outputStream, bufferLength,
            (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                => _pkcs11Library.C_DecryptVerifyUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
            OpDecryptVerifyUpdate);

        byte[]? lastPart = null;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, default, lengthOnly: true, out NativeCULong lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

        lastPart = new byte[ReportedLength.ForAllocation(lastPartLen, OpDecryptFinal)];
        try
        {
            rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, lengthOnly: false, out lastPartLen);
            Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);
            operation.End(CKF.CKF_DECRYPT);

            outputStream.Write(lastPart, 0, ReportedLength.Written(lastPartLen, lastPart.Length, OpDecryptFinal));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(lastPart);
        }

        rv = _pkcs11Library.C_VerifyFinal(_sessionId, signature);
        operation.CompletedIfVerdict(rv);
        bool isValid = IsVerified(rv, OpVerifyFinal, verificationMechanism.Type, signature.Length);

        verificationMechanism.AbsorbOutput(verifyParams);
        decryptionMechanism.AbsorbOutput(decryptParams);
        return isValid;
    }
}
