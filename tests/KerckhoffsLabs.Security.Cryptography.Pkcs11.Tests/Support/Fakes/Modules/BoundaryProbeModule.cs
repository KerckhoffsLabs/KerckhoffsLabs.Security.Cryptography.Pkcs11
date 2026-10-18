using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

/// <summary>
/// A module that uses every byte a caller lends it, as far as the C signature allows: it reads each input
/// buffer to its stated length, writes each output buffer to the capacity the caller stated, reads a
/// mechanism's or message's parameter block to <c>ulParameterLen</c>, and reads a function name up to its
/// NUL. A real module may do any of that, so a wrapper that states a length its buffer does not have is
/// caught here: against <see cref="GuardedMemory"/> the stray access faults.
/// </summary>
/// <remarks>
/// Each buffer the module receives is recorded, in argument order, as the address and length it saw (a
/// function name, which reaches the module only as a C string, as its address-less length with the NUL).
/// Every function answers <c>CKR_OK</c> and leaves an output length at the capacity it was given.
/// </remarks>
internal sealed unsafe class BoundaryProbeModule : FakeModule
{
    private long _sink;

    /// <summary>The buffers received, in the order the module saw them.</summary>
    public List<(IntPtr Address, int Length)> Received { get; } = [];

    private void Read(ReadOnlySpan<byte> input)
    {
        fixed (byte* p = input)
            Received.Add(((IntPtr)p, input.Length));
        foreach (byte b in input)
            _sink += b;
    }

    private void Fill(NativeBuffer<byte> output)
    {
        if (output.IsNull)
            return;
        fixed (byte* p = output.Span)
            Received.Add(((IntPtr)p, output.Span.Length));
        output.Span.Fill(0x5A);
    }

    private void ReadBlock(IntPtr parameter, NativeCULong length)
    {
        if (parameter != IntPtr.Zero)
            Read(new ReadOnlySpan<byte>((void*)parameter, checked((int)(ulong)length)));
    }

    private void ReadMechanism(CK_MECHANISM mechanism) => ReadBlock(mechanism.Parameter, mechanism.ParameterLen);

    private void ReadName(string functionName) => Received.Add((IntPtr.Zero, functionName.Length + 1));

    // Session, token and PIN management.
    protected override CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label) { Read(pin); Read(label); return CKR.CKR_OK; }
    protected override CKR C_InitPIN(NativeCULong session, ReadOnlySpan<byte> pin) { Read(pin); return CKR.CKR_OK; }
    protected override CKR C_SetPIN(NativeCULong session, ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin) { Read(oldPin); Read(newPin); return CKR.CKR_OK; }
    protected override CKR C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin) { Read(pin); return CKR.CKR_OK; }
    protected override CKR C_LoginUser(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> username) { Read(pin); Read(username); return CKR.CKR_OK; }
    protected override CKR C_GetOperationState(NativeCULong session, NativeBuffer<byte> operationState, ref NativeCULong operationStateLen) { Fill(operationState); return CKR.CKR_OK; }
    protected override CKR C_SetOperationState(NativeCULong session, ReadOnlySpan<byte> operationState, NativeCULong encryptionKey, NativeCULong authenticationKey) { Read(operationState); return CKR.CKR_OK; }

    // Operation initialization: only the mechanism's parameter block is lent.
    protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_SignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_SignRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_VerifyRecoverInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_VerifySignatureInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key, ReadOnlySpan<byte> signature) { ReadMechanism(mechanism); Read(signature); return CKR.CKR_OK; }
    protected override CKR C_MessageEncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_MessageDecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_MessageSignInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_MessageVerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }

    // Single- and multi-part operations.
    protected override CKR C_Encrypt(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> encryptedData, ref NativeCULong encryptedDataLen) { Read(data); Fill(encryptedData); return CKR.CKR_OK; }
    protected override CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen) { Read(part); Fill(encryptedPart); return CKR.CKR_OK; }
    protected override CKR C_EncryptFinal(NativeCULong session, NativeBuffer<byte> lastEncryptedPart, ref NativeCULong lastEncryptedPartLen) { Fill(lastEncryptedPart); return CKR.CKR_OK; }
    protected override CKR C_Decrypt(NativeCULong session, ReadOnlySpan<byte> encryptedData, NativeBuffer<byte> data, ref NativeCULong dataLen) { Read(encryptedData); Fill(data); return CKR.CKR_OK; }
    protected override CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen) { Read(encryptedPart); Fill(part); return CKR.CKR_OK; }
    protected override CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen) { Fill(lastPart); return CKR.CKR_OK; }
    protected override CKR C_Digest(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> digest, ref NativeCULong digestLen) { Read(data); Fill(digest); return CKR.CKR_OK; }
    protected override CKR C_DigestUpdate(NativeCULong session, ReadOnlySpan<byte> part) { Read(part); return CKR.CKR_OK; }
    protected override CKR C_DigestFinal(NativeCULong session, NativeBuffer<byte> digest, ref NativeCULong digestLen) { Fill(digest); return CKR.CKR_OK; }
    protected override CKR C_Sign(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) { Read(data); Fill(signature); return CKR.CKR_OK; }
    protected override CKR C_SignUpdate(NativeCULong session, ReadOnlySpan<byte> part) { Read(part); return CKR.CKR_OK; }
    protected override CKR C_SignFinal(NativeCULong session, NativeBuffer<byte> signature, ref NativeCULong signatureLen) { Fill(signature); return CKR.CKR_OK; }
    protected override CKR C_SignRecover(NativeCULong session, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) { Read(data); Fill(signature); return CKR.CKR_OK; }
    protected override CKR C_Verify(NativeCULong session, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) { Read(data); Read(signature); return CKR.CKR_OK; }
    protected override CKR C_VerifyUpdate(NativeCULong session, ReadOnlySpan<byte> part) { Read(part); return CKR.CKR_OK; }
    protected override CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature) { Read(signature); return CKR.CKR_OK; }
    protected override CKR C_VerifyRecover(NativeCULong session, ReadOnlySpan<byte> signature, NativeBuffer<byte> data, ref NativeCULong dataLen) { Read(signature); Fill(data); return CKR.CKR_OK; }
    protected override CKR C_VerifySignature(NativeCULong session, ReadOnlySpan<byte> data) { Read(data); return CKR.CKR_OK; }
    protected override CKR C_VerifySignatureUpdate(NativeCULong session, ReadOnlySpan<byte> part) { Read(part); return CKR.CKR_OK; }

    // Dual-function operations.
    protected override CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen) { Read(part); Fill(encryptedPart); return CKR.CKR_OK; }
    protected override CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen) { Read(encryptedPart); Fill(part); return CKR.CKR_OK; }
    protected override CKR C_SignEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen) { Read(part); Fill(encryptedPart); return CKR.CKR_OK; }
    protected override CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen) { Read(encryptedPart); Fill(part); return CKR.CKR_OK; }

    // Key management.
    protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_GenerateKeyPair(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] publicKeyTemplate, CK_ATTRIBUTE[] privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_DeriveKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong baseKey, CK_ATTRIBUTE[] template, ref NativeCULong key) { ReadMechanism(mechanism); return CKR.CKR_OK; }
    protected override CKR C_WrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen) { ReadMechanism(mechanism); Fill(wrappedKey); return CKR.CKR_OK; }
    protected override CKR C_UnwrapKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ref NativeCULong key) { ReadMechanism(mechanism); Read(wrappedKey); return CKR.CKR_OK; }
    protected override CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key) { ReadMechanism(mechanism); Fill(ciphertext); return CKR.CKR_OK; }
    protected override CKR C_DecapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong privateKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> ciphertext, ref NativeCULong key) { ReadMechanism(mechanism); Read(ciphertext); return CKR.CKR_OK; }
    protected override CKR C_WrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong wrappingKey, NativeCULong key, ReadOnlySpan<byte> associatedData, NativeBuffer<byte> wrappedKey, ref NativeCULong wrappedKeyLen) { ReadMechanism(mechanism); Read(associatedData); Fill(wrappedKey); return CKR.CKR_OK; }
    protected override CKR C_UnwrapKeyAuthenticated(NativeCULong session, CK_MECHANISM mechanism, NativeCULong unwrappingKey, ReadOnlySpan<byte> wrappedKey, CK_ATTRIBUTE[] template, ReadOnlySpan<byte> associatedData, ref NativeCULong key) { ReadMechanism(mechanism); Read(wrappedKey); Read(associatedData); return CKR.CKR_OK; }

    // Random numbers.
    protected override CKR C_SeedRandom(NativeCULong session, ReadOnlySpan<byte> seed) { Read(seed); return CKR.CKR_OK; }
    protected override CKR C_GenerateRandom(NativeCULong session, Span<byte> randomData)
    {
        fixed (byte* p = randomData)
            Received.Add(((IntPtr)p, randomData.Length));
        randomData.Fill(0x5A);
        return CKR.CKR_OK;
    }

    // Message-based operations (v3.0): the parameter block is lent alongside the data.
    protected override CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen) { ReadBlock(parameter, parameterLen); Read(associatedData); Read(plaintext); Fill(ciphertext); return CKR.CKR_OK; }
    protected override CKR C_EncryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData) { ReadBlock(parameter, parameterLen); Read(associatedData); return CKR.CKR_OK; }
    protected override CKR C_EncryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> plaintextPart, NativeBuffer<byte> ciphertextPart, ref NativeCULong ciphertextPartLen, NativeCULong flags) { ReadBlock(parameter, parameterLen); Read(plaintextPart); Fill(ciphertextPart); return CKR.CKR_OK; }
    protected override CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, NativeBuffer<byte> plaintext, ref NativeCULong plaintextLen) { ReadBlock(parameter, parameterLen); Read(associatedData); Read(ciphertext); Fill(plaintext); return CKR.CKR_OK; }
    protected override CKR C_DecryptMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData) { ReadBlock(parameter, parameterLen); Read(associatedData); return CKR.CKR_OK; }
    protected override CKR C_DecryptMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> ciphertextPart, NativeBuffer<byte> plaintextPart, ref NativeCULong plaintextPartLen, NativeCULong flags) { ReadBlock(parameter, parameterLen); Read(ciphertextPart); Fill(plaintextPart); return CKR.CKR_OK; }
    protected override CKR C_SignMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) { ReadBlock(parameter, parameterLen); Read(data); Fill(signature); return CKR.CKR_OK; }
    protected override CKR C_SignMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) { ReadBlock(parameter, parameterLen); return CKR.CKR_OK; }
    protected override CKR C_SignMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, NativeBuffer<byte> signature, ref NativeCULong signatureLen) { ReadBlock(parameter, parameterLen); Read(data); Fill(signature); return CKR.CKR_OK; }
    protected override CKR C_VerifyMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) { ReadBlock(parameter, parameterLen); Read(data); Read(signature); return CKR.CKR_OK; }
    protected override CKR C_VerifyMessageBegin(NativeCULong session, IntPtr parameter, NativeCULong parameterLen) { ReadBlock(parameter, parameterLen); return CKR.CKR_OK; }
    protected override CKR C_VerifyMessageNext(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) { ReadBlock(parameter, parameterLen); Read(data); Read(signature); return CKR.CKR_OK; }

    // Asynchronous operations (v3.2): the function name is a NUL-terminated C string.
    protected override CKR C_AsyncComplete(NativeCULong session, string functionName, ref CK_ASYNC_DATA result) { ReadName(functionName); return CKR.CKR_OK; }
    protected override CKR C_AsyncGetID(NativeCULong session, string functionName, ref NativeCULong id) { ReadName(functionName); return CKR.CKR_OK; }
    protected override CKR C_AsyncJoin(NativeCULong session, string functionName, NativeCULong id, ReadOnlySpan<byte> data) { ReadName(functionName); Read(data); return CKR.CKR_OK; }
}
