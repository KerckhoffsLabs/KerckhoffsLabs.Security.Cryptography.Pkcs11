using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// Digests the value of a secret key
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="keyHandle">Handle of the secret key to be digested</param>
    /// <returns>Digest</returns>
    public byte[] DigestKey(Mechanism mechanism, ObjectHandle keyHandle)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Digest);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestKey");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("DigestKey");
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, in ckMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        rv = _pkcs11Library.C_DigestKey(_sessionId, (NativeCULong)(keyHandle.ObjectId));
        Pkcs11Exception.ThrowIfError(rv, OpDigestKey);

        byte[] digest = CallWithLengthProbe(
            (Span<byte> buffer, bool lengthOnly, out NativeCULong length) => _pkcs11Library.C_DigestFinal(_sessionId, buffer, lengthOnly, out length),
            OpDigestFinal,
            KnownOutputLength.Of(mechanism.Type));
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        return digest;
    }

    /// <summary>
    /// Computes a digest over <paramref name="data"/> using the given mechanism. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list (raw MD5 / SHA-1) and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">The digest mechanism (typically <see cref="CKM.CKM_SHA256"/> or stronger).</param>
    /// <param name="data">Data to digest.</param>
    /// <returns>Digest bytes (length depends on the mechanism — 32 for SHA-256, 48 for SHA-384, 64 for SHA-512).</returns>
    public byte[] Digest(Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Digest);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest1");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Digest");
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, in ckMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        byte[] digest = CallWithLengthProbe(data,
            (ReadOnlySpan<byte> input, Span<byte> buf, bool lengthOnly, out NativeCULong len) => _pkcs11Library.C_Digest(_sessionId, input, buf, lengthOnly, out len),
            OpDigest,
            KnownOutputLength.Of(mechanism.Type),
            () => _pkcs11Library.C_DigestInit(_sessionId, in ckMechanism));
        operation.Completed();

        // Absorbed before returning, so the scope that owns the parameter block is still alive.
        mechanism.AbsorbOutput(mechParams);

        return digest;
    }

    /// <summary>
    /// Digests single-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="data">Data to be digested</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return Digest(mechanism, data.AsSpan());
    }

    /// <summary>
    /// Digests multi-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, Stream inputStream)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Digest);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest2");

        ArgumentNullException.ThrowIfNull(inputStream);

        return Digest(mechanism, inputStream, 4096);
    }

    /// <summary>
    /// Digests multi-part data
    /// </summary>
    /// <param name="mechanism">Digesting mechanism</param>
    /// <param name="inputStream">Input stream from which data should be read</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] Digest(Mechanism mechanism, Stream inputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Digest);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Digest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Digest");
        CKR rv = _pkcs11Library.C_DigestInit(_sessionId, in ckMechanism);
        operation.Begin(CKF.CKF_DIGEST, rv, OpDigestInit);

        byte[] part = new byte[bufferLength];
        int bytesRead = 0;

        while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
        {
            rv = _pkcs11Library.C_DigestUpdate(_sessionId, part.AsSpan(0, bytesRead));
            Pkcs11Exception.ThrowIfError(rv, OpDigestUpdate);
        }

        byte[] digest = CallWithLengthProbe(
            (Span<byte> buffer, bool lengthOnly, out NativeCULong length) => _pkcs11Library.C_DigestFinal(_sessionId, buffer, lengthOnly, out length),
            OpDigestFinal,
            KnownOutputLength.Of(mechanism.Type));
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        return digest;
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="digest">Digest</param>
    /// <param name="encryptedData">Encrypted data</param>
    public void DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, byte[] data, out byte[] digest, out byte[] encryptedData)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(encryptionMechanism, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt1");

        ArgumentNullException.ThrowIfNull(data);

        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new();
        digest = DigestEncrypt(digestingMechanism, encryptionMechanism, keyHandle, inputMemoryStream, outputMemorySteam);
        encryptedData = outputMemorySteam.ToArray();
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <returns>Digest</returns>
    public byte[] DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(encryptionMechanism, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        return DigestEncrypt(digestingMechanism, encryptionMechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Digests and encrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="encryptionMechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where encrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] DigestEncrypt(Mechanism digestingMechanism, Mechanism encryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(encryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(encryptionMechanism, CryptoOperation.Encrypt);

        ThrowIfOneDescriptorDrivesBothHalves(digestingMechanism, encryptionMechanism, nameof(encryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DigestEncrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        return DigestAndTransformStream(
            digestingMechanism, encryptionMechanism, keyHandle, inputStream, outputStream, bufferLength,
            new CombinedTransform(
                Init: (in CK_MECHANISM mechanism, NativeCULong key)
                    => _pkcs11Library.C_EncryptInit(_sessionId, in mechanism, key),
                InitOperation: OpEncryptInit,
                Update: (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                    => _pkcs11Library.C_DigestEncryptUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
                UpdateOperation: OpDigestEncryptUpdate,
                Final: (Span<byte> buffer, bool lengthOnly, out NativeCULong length)
                    => _pkcs11Library.C_EncryptFinal(_sessionId, buffer, lengthOnly, out length),
                FinalOperation: OpEncryptFinal,
                CancelFlag: CKF.CKF_ENCRYPT),
            "DigestEncrypt");
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="data">Data to be processed</param>
    /// <param name="digest">Digest</param>
    /// <param name="decryptedData">Decrypted data</param>
    public void DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, byte[] data, out byte[] digest, out byte[] decryptedData)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest1");

        ArgumentNullException.ThrowIfNull(data);

        using MemoryStream inputMemoryStream = new(data), outputMemorySteam = new();
        digest = DecryptDigest(digestingMechanism, decryptionMechanism, keyHandle, inputMemoryStream, outputMemorySteam);
        decryptedData = outputMemorySteam.ToArray();
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <returns>Digest</returns>
    public byte[] DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        return DecryptDigest(digestingMechanism, decryptionMechanism, keyHandle, inputStream, outputStream, 4096);
    }

    /// <summary>
    /// Digests and decrypts data
    /// </summary>
    /// <param name="digestingMechanism">Digesting mechanism</param>
    /// <param name="decryptionMechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="inputStream">Input stream from which data to be processed should be read</param>
    /// <param name="outputStream">Output stream where decrypted data should be written</param>
    /// <param name="bufferLength">Size of read buffer in bytes</param>
    /// <returns>Digest</returns>
    public byte[] DecryptDigest(Mechanism digestingMechanism, Mechanism decryptionMechanism, ObjectHandle keyHandle, Stream inputStream, Stream outputStream, int bufferLength)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(digestingMechanism);

        ArgumentNullException.ThrowIfNull(decryptionMechanism);


        Enforce(digestingMechanism, CryptoOperation.Digest);
        Enforce(decryptionMechanism, CryptoOperation.Decrypt);

        ThrowIfOneDescriptorDrivesBothHalves(digestingMechanism, decryptionMechanism, nameof(decryptionMechanism));

        Log.SessionTrace(_logger, (ulong)_sessionId, "DecryptDigest3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        return DigestAndTransformStream(
            digestingMechanism, decryptionMechanism, keyHandle, inputStream, outputStream, bufferLength,
            new CombinedTransform(
                Init: (in CK_MECHANISM mechanism, NativeCULong key)
                    => _pkcs11Library.C_DecryptInit(_sessionId, in mechanism, key),
                InitOperation: OpDecryptInit,
                Update: (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                    => _pkcs11Library.C_DecryptDigestUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
                UpdateOperation: OpDecryptDigestUpdate,
                Final: (Span<byte> buffer, bool lengthOnly, out NativeCULong length)
                    => _pkcs11Library.C_DecryptFinal(_sessionId, buffer, lengthOnly, out length),
                FinalOperation: OpDecryptFinal,
                CancelFlag: CKF.CKF_DECRYPT),
            "DecryptDigest");
    }
}
