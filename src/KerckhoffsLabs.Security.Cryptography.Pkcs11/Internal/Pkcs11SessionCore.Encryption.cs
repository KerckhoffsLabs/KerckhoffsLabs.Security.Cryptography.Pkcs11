using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;

using static KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal.Pkcs11Operations;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

internal sealed partial class Pkcs11SessionCore
{
    /// <summary>
    /// Encrypts <paramref name="data"/> using the given mechanism and key. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">The encryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to encrypt with.</param>
    /// <param name="data">Plaintext to encrypt.</param>
    /// <returns>A freshly-allocated byte array containing the ciphertext.</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data)
    {
        // Size the output for the largest single-block expansion a symmetric mechanism adds — a full
        // block of PKCS padding (AES block = 16) or a 16-byte AEAD tag — so block and AEAD ciphers
        // finish in one C_Encrypt without a null-length probe (which makes some AEAD tokens run the
        // whole operation on the probe). This also sidesteps NSS softoken's broken single-part CBC-PAD
        // path, whose short-buffer C_Encrypt feeds the input through EncryptUpdate/Final and does not
        // report the required length. RSA and other output-larger-than-input mechanisms still grow via
        // the CKR_BUFFER_TOO_SMALL retry.
        byte[] encryptedData = new byte[data.Length + 16];
        RunSinglePart(encrypt: true, mechanism, keyHandle, data, encryptedData, growIfNeeded: true, out int written, out byte[]? grown);
        return grown ?? ReportedLength.Trim(encryptedData, (NativeCULong)(ulong)written, OpEncrypt);
    }

    /// <summary>
    /// Encrypts <paramref name="data"/> into <paramref name="destination"/>. Returns <see langword="false"/>
    /// only when the ciphertext is longer than <paramref name="destination"/>; <paramref name="written"/>
    /// is then its length, the operation has still been completed, and <paramref name="destination"/>
    /// is cleared.
    /// </summary>
    internal bool TryEncrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> data, Span<byte> destination, out int written)
        => RunSinglePart(encrypt: true, mechanism, keyHandle, data, destination, growIfNeeded: false, out written, out _);

    /// <summary>
    /// Encrypts single-part data
    /// </summary>
    /// <param name="mechanism">Encryption mechanism</param>
    /// <param name="keyHandle">Handle of the encryption key</param>
    /// <param name="data">Data to be encrypted</param>
    /// <returns>Encrypted data</returns>
    public byte[] Encrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return Encrypt(mechanism, keyHandle, data.AsSpan());
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
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

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
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);


        Enforce(mechanism, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Encrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Encrypt");
        CKR rv = _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_ENCRYPT, rv, OpEncryptInit);

        PumpStreamThrough(inputStream, outputStream, bufferLength,
            (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                => _pkcs11Library.C_EncryptUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
            OpEncryptUpdate);

        byte[]? lastEncryptedPart = null;
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, default, lengthOnly: true, out NativeCULong lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);

        lastEncryptedPart = new byte[ReportedLength.ForAllocation(lastEncryptedPartLen, OpEncryptFinal)];
        rv = _pkcs11Library.C_EncryptFinal(_sessionId, lastEncryptedPart, lengthOnly: false, out lastEncryptedPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpEncryptFinal);
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        outputStream.Write(lastEncryptedPart, 0, ReportedLength.Written(lastEncryptedPartLen, lastEncryptedPart.Length, OpEncryptFinal));
    }

    /// <summary>
    /// True when the loaded PKCS#11 library exposes the v3.0 message-based AEAD API
    /// (<see cref="MessageEncrypt"/> / <see cref="MessageDecrypt"/> use it). False on
    /// v2.40 libraries — callers must use <see cref="Encrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/> / <see cref="Decrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/>
    /// with the legacy CK_GCM_PARAMS / CK_CCM_PARAMS / CK_SALSA20_CHACHA20_POLY1305_PARAMS
    /// instead.
    /// </summary>
    public bool SupportsMessageApi => _pkcs11Library.IsMessageApiSupported;

    /// <summary>
    /// Whether <c>CK_GCM_PARAMS</c> sent to this session's module carries the IV length in
    /// <c>ulIvBits</c>, rather than 0: when the module was bound through a v3.x interface. See
    /// <see cref="CkmAesGcmParams"/>.
    /// </summary>
    internal bool SendsGcmIvBits => _pkcs11Library.IsBoundThroughV3Interface;

    /// <summary>
    /// Whether <c>CKM_PKCS5_PBKD2</c> must send this session's slot the original
    /// <c>CK_PKCS5_PBKD2_PARAMS</c>, whose <c>ulPasswordLen</c> is a pointer: as
    /// <see cref="Pkcs11LibraryOptions.Pbkdf2ParametersLayout"/> configured it, or else as detected the
    /// first time a session on this slot asks (<see cref="DetectPbkdf2PasswordLengthByReference"/>).
    /// </summary>
    /// <remarks>
    /// A method, not a property: the first call on a slot asks the module through <c>C_GetSlotInfo</c>
    /// and possibly <c>C_GetInfo</c>, and may throw.
    /// </remarks>
    /// <exception cref="Pkcs11Exception"><c>C_GetSlotInfo</c> or <c>C_GetInfo</c> failed.</exception>
    internal bool ResolvePbkdf2PasswordLengthByReference()
    {
        if (_pkcs11Library.Pbkdf2PasswordLengthByReference is { } configured)
            return configured;

        ConcurrentDictionary<ulong, bool> bySlot = _pkcs11Library.Pbkdf2PasswordLengthByReferenceBySlot;
        if (bySlot.TryGetValue((ulong)_slotId, out bool known))
            return known;

        bool byReference = DetectPbkdf2PasswordLengthByReference(_slotId, out string reason);
        Log.Pbkdf2Layout(_logger, (ulong)_sessionId,
            byReference ? "CK_PKCS5_PBKD2_PARAMS" : "CK_PKCS5_PBKD2_PARAMS2", (ulong)_slotId, reason);
        return bySlot.GetOrAdd((ulong)_slotId, byReference);
    }

    /// <summary>
    /// Whether the module behind <paramref name="slotId"/> reads the original
    /// <c>CK_PKCS5_PBKD2_PARAMS</c>: an NSS softoken slot before 3.114, recognized from
    /// <c>C_GetSlotInfo</c> whether NSS is loaded directly or behind a proxy such as p11-kit's; or else a
    /// module implementing a Cryptoki version before 2.40, from <c>C_GetInfo</c>. See
    /// <see cref="CkmPkcs5Pbkd2Params.ReadsPasswordLengthByReference(SlotInfo)"/>.
    /// </summary>
    /// <remarks>
    /// A module that does not implement one of those functions is judged without it. Any other failure
    /// throws and decides nothing: guessing would crash the process on an NSS slot, and a later call may
    /// well succeed.
    /// </remarks>
    /// <exception cref="Pkcs11Exception"><c>C_GetSlotInfo</c> or <c>C_GetInfo</c> failed.</exception>
    private bool DetectPbkdf2PasswordLengthByReference(NativeCULong slotId, out string reason)
    {
        CK_SLOT_INFO slot = default;
        CKR rv = _pkcs11Library.C_GetSlotInfo(slotId, ref slot);
        if (rv != CKR.CKR_FUNCTION_NOT_SUPPORTED)
        {
            Pkcs11Exception.ThrowIfError(rv, OpGetSlotInfo);
            var slotInfo = new SlotInfo(slotId, slot);
            if (CkmPkcs5Pbkd2Params.IsNss(slotInfo))
            {
                reason = $"NSS {slotInfo.HardwareVersion}";
                return CkmPkcs5Pbkd2Params.ReadsPasswordLengthByReference(slotInfo);
            }
        }

        CK_INFO info = default;
        rv = _pkcs11Library.C_GetInfo(ref info);
        if (rv == CKR.CKR_FUNCTION_NOT_SUPPORTED)
        {
            reason = "module version unknown";
            return false;
        }
        Pkcs11Exception.ThrowIfError(rv, OpGetInfo);
        var libraryInfo = new LibraryInfo(info);
        reason = $"Cryptoki {libraryInfo.CryptokiVersion}";
        return CkmPkcs5Pbkd2Params.ReadsPasswordLengthByReference(libraryInfo);
    }

    /// <summary>
    /// One-shot AEAD encrypt via the PKCS#11 v3.0 message-based API
    /// (C_MessageEncryptInit + C_EncryptMessage + C_MessageEncryptFinal). The per-message
    /// nonce / IV / tag flow lives entirely in <paramref name="messageParams"/>; the
    /// authentication tag is read back through the wrapper's <c>CopyTagTo</c> /
    /// <c>CopyMacTo</c> method after this call.
    /// </summary>
    /// <param name="mechanism">AEAD mechanism (CKM_AES_GCM / CKM_AES_CCM / CKM_CHACHA20_POLY1305 / CKM_SALSA20_POLY1305).</param>
    /// <param name="keyHandle">Symmetric key handle.</param>
    /// <param name="messageParams">Per-message parameters (e.g. <see cref="CkmGcmMessageParams"/>).</param>
    /// <param name="associatedData">Optional Additional Authenticated Data.</param>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <returns>Ciphertext (without the tag — tag is in <paramref name="messageParams"/>).</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> when the loaded library is v2.40.</exception>
    public byte[] MessageEncrypt(
        Mechanism mechanism,
        ObjectHandle keyHandle,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> plaintext)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        EnforceMessage(mechanism, messageParams, CryptoOperation.Encrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "MessageEncrypt");

        // One scope for the whole operation: it owns the mechanism's parameter block and the
        // per-message block below, and outlives every native call that reads or writes them.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);
        CKR rv = _pkcs11Library.C_MessageEncryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, OpMessageEncryptInit);

        mechanism.AbsorbOutput(mechParams);

        try
        {
            Pkcs11ParameterBlock messageBlock = messageParams.BuildMarshalable(scope);

            byte[] ct = CallWithLengthProbe(associatedData, plaintext,
                (ReadOnlySpan<byte> ad, ReadOnlySpan<byte> pt, Span<byte> buf, bool lengthOnly, out NativeCULong len)
                    => _pkcs11Library.C_EncryptMessage(_sessionId, messageBlock.Pointer, (NativeCULong)messageBlock.Length, ad, pt, buf, lengthOnly, out len),
                OpEncryptMessage,
                KeepsTagInTheParameter(mechanism.Type) ? plaintext.Length : null);

            // The token wrote the authentication tag into the scope-owned block; copy it back into
            // the wrapper before `scope` is disposed and the bytes are zeroized.
            messageParams.AbsorbOutput(messageBlock);

            return ct;
        }
        finally
        {
            CKR finalRv = _pkcs11Library.C_MessageEncryptFinal(_sessionId);
            if (finalRv != CKR.CKR_OK)
                Log.MessageEncryptFinalFailed(_logger, finalRv);
        }
    }

    /// <summary>
    /// Decrypts <paramref name="encryptedData"/> using the given mechanism and key. Throws
    /// <see cref="CryptoPolicyViolationException"/> if <paramref name="mechanism"/> is on the
    /// insecure-by-default list and the session's policy refuses the mechanism.
    /// </summary>
    /// <param name="mechanism">The decryption mechanism to use.</param>
    /// <param name="keyHandle">Handle of the key to decrypt with.</param>
    /// <param name="encryptedData">Ciphertext to decrypt.</param>
    /// <returns>A freshly-allocated byte array containing the plaintext.</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> encryptedData)
    {
        // The input length as the output size: plaintext is never longer than its ciphertext for the
        // mechanisms in use, it avoids a null-length probe (which makes AEAD tokens such as SoftHSM run
        // the whole tag check and answer with an opaque error), and it is what modules that size the
        // output from the input ask for.
        byte[] decryptedData = new byte[encryptedData.Length];
        RunSinglePart(encrypt: false, mechanism, keyHandle, encryptedData, decryptedData, growIfNeeded: true, out int written, out byte[]? grown);
        return grown ?? ReportedLength.Trim(decryptedData, (NativeCULong)(ulong)written, OpDecrypt);
    }

    /// <summary>
    /// Decrypts <paramref name="encryptedData"/> into <paramref name="destination"/>. Returns
    /// <see langword="false"/> only when the plaintext is longer than <paramref name="destination"/>;
    /// <paramref name="written"/> is then its length, the operation has still been completed, and
    /// <paramref name="destination"/> is cleared.
    /// </summary>
    /// <remarks>
    /// A module that wants an output buffer larger than the plaintext (SoftHSM 2.7's AEAD decrypt asks
    /// for the ciphertext's length) does not make this fail: the plaintext goes through a zeroized
    /// <see cref="ScratchBuffer"/> instead, and after the first time the quirk is known for the slot and
    /// mechanism, so later decrypts go there directly in one call.
    /// </remarks>
    internal bool TryDecrypt(Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> encryptedData, Span<byte> destination, out int written)
        => RunSinglePart(encrypt: false, mechanism, keyHandle, encryptedData, destination, growIfNeeded: false, out written, out _);

    /// <summary>
    /// One single-part <c>C_Encrypt</c> or <c>C_Decrypt</c>, from the policy check to the result, writing
    /// into <paramref name="destination"/>.
    /// </summary>
    /// <param name="encrypt">Encrypt, or decrypt.</param>
    /// <param name="mechanism">The mechanism.</param>
    /// <param name="keyHandle">The key.</param>
    /// <param name="input">The data to transform.</param>
    /// <param name="destination">Where the output goes when it fits.</param>
    /// <param name="growIfNeeded">
    /// When the output does not fit, return it in <paramref name="grown"/>, a new array of exactly its
    /// length, instead of returning <see langword="false"/>.
    /// </param>
    /// <param name="written">The output's length, whether or not it fit.</param>
    /// <param name="grown">The output, when it did not fit and <paramref name="growIfNeeded"/> was set.</param>
    /// <returns><see langword="false"/> when the output did not fit and was not kept.</returns>
    private bool RunSinglePart(bool encrypt, Mechanism mechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> input,
        Span<byte> destination, bool growIfNeeded, out int written, out byte[]? grown)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, encrypt ? CryptoOperation.Encrypt : CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, encrypt ? "Encrypt" : "Decrypt");

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation(encrypt ? "Encrypt" : "Decrypt");
        CKR rv = InitSinglePart(encrypt, ref ckMechanism, keyHandle);
        operation.Begin(encrypt ? CKF.CKF_ENCRYPT : CKF.CKF_DECRYPT, rv, encrypt ? OpEncryptInit : OpDecryptInit);

        bool kept;
        try
        {
            kept = TransformSinglePart(encrypt, ref ckMechanism, keyHandle, mechanism.Type, input, destination, growIfNeeded, out written, out grown);
        }
        catch
        {
            // Whatever the module wrote before failing is not left behind.
            CryptographicOperations.ZeroMemory(destination);
            throw;
        }
        operation.Completed();

        // Inside the scope's lifetime: the parameter block the token may have written into (an AEAD
        // IV, say) is still allocated. After `scope` is disposed the bytes are zeroized and freed.
        mechanism.AbsorbOutput(mechParams);

        return kept;
    }

    /// <summary>
    /// The transforming call of <see cref="RunSinglePart"/>, on an initialized operation. Whatever
    /// happens, the operation is finished when this returns or throws, and
    /// <paramref name="destination"/> holds output only if this returns <see langword="true"/> without
    /// <paramref name="grown"/>.
    /// </summary>
    private bool TransformSinglePart(bool encrypt, ref CK_MECHANISM ckMechanism, ObjectHandle keyHandle, CKM mechanismType,
        ReadOnlySpan<byte> input, Span<byte> destination, bool growIfNeeded, out int written, out byte[]? grown)
    {
        string function = encrypt ? OpEncrypt : OpDecrypt;

        var quirkKey = ((ulong)_slotId, mechanismType);
        if (!encrypt && destination.Length < input.Length
            && _pkcs11Library.DecryptWantsInputSizedOutput.ContainsKey(quirkKey))
        {
            byte[] scratch = FinishSinglePartInScratch(encrypt, ref ckMechanism, keyHandle, input, input.Length, out written);
            return DeliverFromScratch(scratch, written, destination, growIfNeeded, out grown);
        }

        CKR rv = CallSinglePart(encrypt, input, destination, lengthOnly: false, out NativeCULong length);
        if (rv == CKR.CKR_OK)
        {
            grown = null;
            written = ReportedLength.Written(length, destination.Length, function);
            return true;
        }

        CryptographicOperations.ZeroMemory(destination);
        if (rv != CKR.CKR_BUFFER_TOO_SMALL)
            throw Pkcs11Exception.Create(rv, function);

        // PKCS#11 v3.2 §5.2: the module reports the length it needs and leaves the operation active. A
        // length no longer than the destination was not reported (opencryptoki leaves the caller's in
        // place), so it is asked for; NSS answers that query with CKR_OPERATION_NOT_INITIALIZED, having
        // ended the operation, which is then started again.
        if ((ulong)length <= (ulong)destination.Length)
        {
            rv = CallSinglePart(encrypt, input, default, lengthOnly: true, out length);
            if (rv == CKR.CKR_OPERATION_NOT_INITIALIZED)
                length = RestartSinglePart(encrypt, ref ckMechanism, keyHandle, input);
            else
                Pkcs11Exception.ThrowIfError(rv, function);
        }

        // The reported length can exceed the result (a module that sizes the output from the input), so
        // the operation is finished in a buffer of that size and the result itself decides.
        byte[] sized = FinishSinglePartInScratch(encrypt, ref ckMechanism, keyHandle, input,
            ReportedLength.ForAllocation(length, function), out written);
        if (!encrypt && written <= destination.Length)
            _pkcs11Library.DecryptWantsInputSizedOutput.TryAdd(quirkKey, true);
        return DeliverFromScratch(sized, written, destination, growIfNeeded, out grown);
    }

    /// <summary>
    /// Finishes an active single-part operation into a <see cref="ScratchBuffer"/> of
    /// <paramref name="size"/> bytes, the size the module asked for, or of the size the array-returning
    /// <see cref="Encrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/> and
    /// <see cref="Decrypt(Mechanism, ObjectHandle, ReadOnlySpan{byte})"/> start with when that is larger.
    /// The caller returns the buffer.
    /// </summary>
    /// <remarks>
    /// The reported size is not trusted below that floor: NSS softoken answers a length query with the
    /// input length plus two cipher blocks, and its AES-GCM context has a block size of 0, so the length
    /// it reports has no room for the tag. Nor does it report one on <c>CKR_BUFFER_TOO_SMALL</c>.
    /// A <c>CKR_BUFFER_TOO_SMALL</c> here is followed once, at the size the module then reports. A module
    /// that ends the operation on <c>CKR_BUFFER_TOO_SMALL</c>, against PKCS#11 v3.2 §5.2 (NSS softoken's
    /// classic <c>C_Encrypt</c> and <c>C_Decrypt</c> do), answers the next call with
    /// <c>CKR_OPERATION_NOT_INITIALIZED</c>: the operation is then started again, its length queried, and
    /// run once.
    /// </remarks>
    private byte[] FinishSinglePartInScratch(bool encrypt, ref CK_MECHANISM ckMechanism, ObjectHandle keyHandle,
        ReadOnlySpan<byte> input, int size, out int written)
    {
        string function = encrypt ? OpEncrypt : OpDecrypt;
        int floor = encrypt ? (int)Math.Min((long)input.Length + 16, Array.MaxLength) : input.Length;
        size = Math.Max(size, floor);
        byte[] scratch = ScratchBuffer.Rent(size);
        try
        {
            CKR rv = CallSinglePart(encrypt, input, scratch.AsSpan(0, size), lengthOnly: false, out NativeCULong length);
            if (rv == CKR.CKR_BUFFER_TOO_SMALL && (ulong)length > (ulong)size)
            {
                size = ReportedLength.ForAllocation(length, function);
                ScratchBuffer.Return(scratch);
                scratch = ScratchBuffer.Rent(size);
                rv = CallSinglePart(encrypt, input, scratch.AsSpan(0, size), lengthOnly: false, out length);
            }

            if (rv == CKR.CKR_OPERATION_NOT_INITIALIZED)
            {
                int needed = Math.Max(ReportedLength.ForAllocation(RestartSinglePart(encrypt, ref ckMechanism, keyHandle, input), function), floor);
                if (needed > scratch.Length)
                {
                    ScratchBuffer.Return(scratch);
                    scratch = ScratchBuffer.Rent(needed);
                }
                size = needed;
                rv = CallSinglePart(encrypt, input, scratch.AsSpan(0, size), lengthOnly: false, out length);
            }

            Pkcs11Exception.ThrowIfError(rv, function);
            written = ReportedLength.Written(length, size, function);
            return scratch;
        }
        catch
        {
            ScratchBuffer.Return(scratch);
            throw;
        }
    }

    /// <summary>
    /// Starts the single-part operation again, after a module ended it on <c>CKR_BUFFER_TOO_SMALL</c>,
    /// and returns the output length it reports.
    /// </summary>
    private NativeCULong RestartSinglePart(bool encrypt, ref CK_MECHANISM ckMechanism, ObjectHandle keyHandle, ReadOnlySpan<byte> input)
    {
        CKR rv = InitSinglePart(encrypt, ref ckMechanism, keyHandle);
        Pkcs11Exception.ThrowIfError(rv, encrypt ? OpEncryptInit : OpDecryptInit);

        rv = CallSinglePart(encrypt, input, default, lengthOnly: true, out NativeCULong length);
        Pkcs11Exception.ThrowIfError(rv, encrypt ? OpEncrypt : OpDecrypt);
        return length;
    }

    /// <summary>
    /// Moves a finished result out of <paramref name="scratch"/>, which is returned here: into
    /// <paramref name="destination"/> when it fits, into a new array when it does not and
    /// <paramref name="growIfNeeded"/> is set, and nowhere otherwise. <paramref name="destination"/> is
    /// cleared whenever it does not receive the result, so a <see langword="false"/> leaves it the same
    /// on every path.
    /// </summary>
    private static bool DeliverFromScratch(byte[] scratch, int written, Span<byte> destination, bool growIfNeeded, out byte[]? grown)
    {
        try
        {
            grown = null;
            if (written <= destination.Length)
            {
                scratch.AsSpan(0, written).CopyTo(destination);
                return true;
            }
            CryptographicOperations.ZeroMemory(destination);
            if (growIfNeeded)
            {
                grown = scratch.AsSpan(0, written).ToArray();
                return true;
            }
            return false;
        }
        finally
        {
            ScratchBuffer.Return(scratch);
        }
    }

    private CKR InitSinglePart(bool encrypt, ref CK_MECHANISM ckMechanism, ObjectHandle keyHandle)
        => encrypt
            ? _pkcs11Library.C_EncryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId)
            : _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);

    private CKR CallSinglePart(bool encrypt, ReadOnlySpan<byte> input, Span<byte> output, bool lengthOnly, out NativeCULong length)
        => encrypt
            ? _pkcs11Library.C_Encrypt(_sessionId, input, output, lengthOnly, out length)
            : _pkcs11Library.C_Decrypt(_sessionId, input, output, lengthOnly, out length);

    /// <summary>
    /// Decrypts single-part data
    /// </summary>
    /// <param name="mechanism">Decryption mechanism</param>
    /// <param name="keyHandle">Handle of the decryption key</param>
    /// <param name="encryptedData">Data to be decrypted</param>
    /// <returns>Decrypted data</returns>
    public byte[] Decrypt(Mechanism mechanism, ObjectHandle keyHandle, byte[] encryptedData)
    {
        ArgumentNullException.ThrowIfNull(encryptedData);
        return Decrypt(mechanism, keyHandle, encryptedData.AsSpan());
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
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Decrypt2");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

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
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);

        Enforce(mechanism, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "Decrypt3");

        ArgumentNullException.ThrowIfNull(inputStream);

        ArgumentNullException.ThrowIfNull(outputStream);

        if (bufferLength < 1)
            throw new ArgumentException(ValueMustBePositive, nameof(bufferLength));

        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);

        using var operation = BeginOperation("Decrypt");
        CKR rv = _pkcs11Library.C_DecryptInit(_sessionId, ref ckMechanism, (NativeCULong)(keyHandle.ObjectId));
        operation.Begin(CKF.CKF_DECRYPT, rv, OpDecryptInit);

        PumpStreamThrough(inputStream, outputStream, bufferLength,
            (ReadOnlySpan<byte> input, Span<byte> output, out NativeCULong outputLen)
                => _pkcs11Library.C_DecryptUpdate(_sessionId, input, output, lengthOnly: false, out outputLen),
            OpDecryptUpdate);

        byte[]? lastPart = null;
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, default, lengthOnly: true, out NativeCULong lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);

        lastPart = new byte[ReportedLength.ForAllocation(lastPartLen, OpDecryptFinal)];
        rv = _pkcs11Library.C_DecryptFinal(_sessionId, lastPart, lengthOnly: false, out lastPartLen);
        Pkcs11Exception.ThrowIfError(rv, OpDecryptFinal);
        operation.Completed();

        mechanism.AbsorbOutput(mechParams);

        outputStream.Write(lastPart, 0, ReportedLength.Written(lastPartLen, lastPart.Length, OpDecryptFinal));
        CryptographicOperations.ZeroMemory(lastPart);
    }

    /// <summary>
    /// One-shot AEAD decrypt via the PKCS#11 v3.0 message-based API
    /// (C_MessageDecryptInit + C_DecryptMessage + C_MessageDecryptFinal). The tag is
    /// supplied through <paramref name="messageParams"/> (constructed via the matching
    /// <c>ForDecrypt</c> factory) and verified by the token.
    /// </summary>
    /// <param name="mechanism">AEAD mechanism.</param>
    /// <param name="keyHandle">Symmetric key handle.</param>
    /// <param name="messageParams">Per-message parameters carrying the nonce and tag.</param>
    /// <param name="associatedData">Optional AAD that was bound at encrypt time.</param>
    /// <param name="ciphertext">Ciphertext bytes (without the tag).</param>
    /// <returns>Plaintext.</returns>
    /// <exception cref="Pkcs11Exception"><see cref="CKR.CKR_FUNCTION_NOT_SUPPORTED"/> on v2.40 libraries; <see cref="CKR.CKR_AEAD_DECRYPT_FAILED"/> on tag-verification failure.</exception>
    public byte[] MessageDecrypt(
        Mechanism mechanism,
        ObjectHandle keyHandle,
        MechanismParameters messageParams,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext)
    {
        using var _ = AcquireExclusive();

        ArgumentNullException.ThrowIfNull(mechanism);
        ArgumentNullException.ThrowIfNull(messageParams);

        EnforceMessage(mechanism, messageParams, CryptoOperation.Decrypt);

        Log.SessionTrace(_logger, (ulong)_sessionId, "MessageDecrypt");

        // One scope for the whole operation: it owns the mechanism's parameter block and the
        // per-message block below, and outlives every native call that reads or writes them.
        using var scope = new SessionParameterScope(this);
        CK_MECHANISM ckMechanism = mechanism.Marshal(scope, out Pkcs11ParameterBlock? mechParams);
        CKR rv = _pkcs11Library.C_MessageDecryptInit(_sessionId, ref ckMechanism, (NativeCULong)keyHandle.ObjectId);
        Pkcs11Exception.ThrowIfError(rv, OpMessageDecryptInit);

        mechanism.AbsorbOutput(mechParams);

        try
        {
            Pkcs11ParameterBlock messageBlock = messageParams.BuildMarshalable(scope);

            byte[] pt = CallWithLengthProbe(associatedData, ciphertext,
                (ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ct, Span<byte> buf, bool lengthOnly, out NativeCULong len)
                    => _pkcs11Library.C_DecryptMessage(_sessionId, messageBlock.Pointer, (NativeCULong)messageBlock.Length, ad, ct, buf, lengthOnly, out len),
                OpDecryptMessage,
                KeepsTagInTheParameter(mechanism.Type) ? ciphertext.Length : null);

            messageParams.AbsorbOutput(messageBlock);

            return pt;
        }
        finally
        {
            CKR finalRv = _pkcs11Library.C_MessageDecryptFinal(_sessionId);
            if (finalRv != CKR.CKR_OK)
                Log.MessageDecryptFinalFailed(_logger, finalRv);
        }
    }
}
