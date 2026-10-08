using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the v3.0 message-based AEAD API (<c>MessageEncrypt</c>/<c>MessageDecrypt</c>),
/// the lazily-cached <c>SupportsMechanism</c> probe, and <c>DigestKey</c>. The message API is only
/// reached through the high-level AEAD algorithm wrappers in the Integration suite, so the
/// session-level length-probe and finalize paths are pinned here through a <see cref="FakeModule"/>
/// behind the real loader.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11SessionMessageAndMiscTests
{
    private const ulong SessionId = 11;

    // === Message AEAD =======================================================

    private sealed class MessageFake : SessionTestModule
    {
        public byte[] Ciphertext = [0xC0, 0xC1];
        public byte[] Plaintext = [0xB0, 0xB1]; // overwritten per test
        public CKR EncMsgRv = CKR.CKR_OK, DecMsgRv = CKR.CKR_OK;
        public int EncryptFinalCalls { get; private set; }
        public int DecryptFinalCalls { get; private set; }

        // Stands in for the token's own access to the per-message parameter block, which a real
        // module reads (nonce, tag on decrypt) and writes (tag on encrypt) through its pointer
        // fields. Invoked with the block address during the real call only, never the length probe,
        // because that is when a token touches it. Left null by the tests that only care about
        // ciphertext plumbing.
        public Action<IntPtr>? OnEncryptMessageParams;
        public Action<IntPtr>? OnDecryptMessageParams;

        protected override CKR C_MessageEncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_MessageEncryptFinal(NativeCULong session) { EncryptFinalCalls++; return CKR.CKR_OK; }
        protected override CKR C_MessageDecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_MessageDecryptFinal(NativeCULong session) { DecryptFinalCalls++; return CKR.CKR_OK; }

        protected override CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen)
        {
            if (ciphertext.IsNull) { ciphertextLen = (NativeCULong)Ciphertext.Length; return EncMsgRv; }
            if (ciphertext.Span.Length < Ciphertext.Length) { ciphertextLen = (NativeCULong)Ciphertext.Length; return CKR.CKR_BUFFER_TOO_SMALL; }
            OnEncryptMessageParams?.Invoke(parameter);
            Ciphertext.AsSpan(0, Ciphertext.Length).CopyTo(ciphertext.Span);
            ciphertextLen = (NativeCULong)Ciphertext.Length;
            return EncMsgRv;
        }

        protected override CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, NativeBuffer<byte> plaintext, ref NativeCULong plaintextLen)
        {
            if (plaintext.IsNull) { plaintextLen = (NativeCULong)Plaintext.Length; return DecMsgRv; }
            if (plaintext.Span.Length < Plaintext.Length) { plaintextLen = (NativeCULong)Plaintext.Length; return CKR.CKR_BUFFER_TOO_SMALL; }
            OnDecryptMessageParams?.Invoke(parameter);
            Plaintext.AsSpan(0, Plaintext.Length).CopyTo(plaintext.Span);
            plaintextLen = (NativeCULong)Plaintext.Length;
            return DecMsgRv;
        }
    }


    // The tag length of a message-based AEAD lives in the per-message parameters, not on the mechanism
    // C_MessageEncryptInit receives, so the session must show them to the policy for it to judge the tag.
    [Fact]
    public void MessageEncrypt_ShortGcmTag_IsRefusedByThePolicy_BeforeTheToken()
    {
        using var fake = new MessageFake();
        using var s = fake.CreateSession(SessionId, policy: CryptoPolicy.SecureOnly);
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 8);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
            s.MessageEncrypt(new Mechanism(CKM.CKM_AES_GCM), new ObjectHandle(1), p, associatedData: [], plaintext: [1]));

        Assert.StartsWith("A 64-bit AES-GCM tag", ex.Reason);
        Assert.Equal(0, fake.EncryptFinalCalls); // the operation never started
    }

    [Fact]
    public void MessageDecrypt_ShortCcmMac_IsRefusedByThePolicy_BeforeTheToken()
    {
        using var fake = new MessageFake();
        using var s = fake.CreateSession(SessionId, policy: CryptoPolicy.SecureOnly);
        var p = CkmCcmMessageParams.ForDecrypt(2, new byte[12], new byte[4]);

        var ex = Assert.Throws<CryptoPolicyViolationException>(() =>
            s.MessageDecrypt(new Mechanism(CKM.CKM_AES_CCM), new ObjectHandle(1), p, associatedData: [], ciphertext: [1, 2]));

        Assert.StartsWith("A 32-bit AES-CCM MAC", ex.Reason);
        Assert.Equal(0, fake.DecryptFinalCalls);
    }

    [Fact]
    public void MessageEncrypt_FullGcmTag_IsAllowedByThePolicy()
    {
        using var fake = new MessageFake { Ciphertext = [1, 2] };
        using var s = fake.CreateSession(SessionId, policy: CryptoPolicy.SecureOnly);
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

        Assert.Equal(new byte[] { 1, 2 },
            s.MessageEncrypt(new Mechanism(CKM.CKM_AES_GCM), new ObjectHandle(1), p, associatedData: [], plaintext: [9, 9]));
    }

    [Fact]
    public void MessageEncrypt_Ok_ReturnsCiphertext_AndFinalizes()
    {
        using var fake = new MessageFake { Ciphertext = [1, 2, 3, 4] };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

        byte[] ct = s.MessageEncrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], plaintext: [9, 9, 9]);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, ct);
        Assert.Equal(1, fake.EncryptFinalCalls); // finalized even on the success path
    }

    [Fact]
    public void MessageEncrypt_Error_ThrowsAndFinalizes()
    {
        using var fake = new MessageFake { EncMsgRv = CKR.CKR_DEVICE_ERROR };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.MessageEncrypt(mech, new ObjectHandle(1), p, associatedData: [], plaintext: [1]));
        Assert.Equal(1, fake.EncryptFinalCalls); // finalize runs on the exception unwind
    }

    [Fact]
    public void MessageDecrypt_Ok_ReturnsPlaintext_AndFinalizes()
    {
        using var fake = new MessageFake { Plaintext = [7, 7, 7] };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]);

        byte[] pt = s.MessageDecrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], ciphertext: [1, 2, 3]);

        Assert.Equal(new byte[] { 7, 7, 7 }, pt);
        Assert.Equal(1, fake.DecryptFinalCalls);
    }

    [Fact]
    public void MessageDecrypt_TagFailure_Throws()
    {
        using var fake = new MessageFake { DecMsgRv = CKR.CKR_AEAD_DECRYPT_FAILED };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]);

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.MessageDecrypt(mech, new ObjectHandle(1), p, associatedData: [], ciphertext: [1, 2, 3]));
        Assert.Equal(1, fake.DecryptFinalCalls);
    }

    // === Tag / MAC round-trip through the parameter block ====================
    //
    // The tests above pin the ciphertext and finalize plumbing but never look at the parameter
    // block, so they pass whether or not the AEAD tag survives the trip. These three close that
    // gap from both ends: the token's tag must reach the caller through CopyTagTo/CopyMacTo, and
    // the caller's tag must reach the token for verification. Both directions cross scope-owned
    // memory, so a lifetime or absorb-ordering mistake shows up here as a wrong tag rather than
    // as a crash.

    [Fact]
    public void MessageEncrypt_TagWrittenByToken_ReachesCopyTagTo()
    {
        byte[] tokenTag = new byte[16];
        tokenTag.AsSpan().Fill(0xA7);

        using var fake = new MessageFake
        {
            Ciphertext = [1, 2, 3],
            // What a real module does on encrypt: locate the tag buffer via the block and fill it.
            OnEncryptMessageParams = block =>
            {
                var gcm = UnmanagedMemory.Read<CK_GCM_MESSAGE_PARAMS>(block);
                Assert.NotEqual(IntPtr.Zero, gcm.Tag);
                Assert.Equal(16 * 8, (int)(ulong)gcm.TagBits);
                UnmanagedMemory.Write(gcm.Tag, tokenTag);
            },
        };

        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

        s.MessageEncrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], plaintext: [9, 9, 9]);

        byte[] readBack = new byte[16];
        p.CopyTagTo(readBack);
        Assert.Equal(tokenTag, readBack);
    }

    [Fact]
    public void MessageDecrypt_CallerSuppliedTag_ReachesTheToken()
    {
        byte[] callerTag = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

        byte[]? observed = null;
        using var fake = new MessageFake
        {
            Plaintext = [7, 7, 7],
            // What a real module does on decrypt: read the tag out of the block to verify against.
            OnDecryptMessageParams = block =>
            {
                var gcm = UnmanagedMemory.Read<CK_GCM_MESSAGE_PARAMS>(block);
                Assert.NotEqual(IntPtr.Zero, gcm.Tag);
                observed = UnmanagedMemory.Read(gcm.Tag, (int)(ulong)gcm.TagBits / 8);
            },
        };

        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForDecrypt(new byte[12], callerTag);

        s.MessageDecrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], ciphertext: [1, 2, 3]);

        // Non-null proves the hook ran at all: a block the token never sees would leave this null
        // and pass the equality check below by vacuous omission.
        Assert.NotNull(observed);
        Assert.Equal(callerTag, observed);
    }

    [Fact]
    public void MessageEncrypt_MacWrittenByToken_ReachesCopyMacTo()
    {
        byte[] tokenMac = new byte[16];
        tokenMac.AsSpan().Fill(0x5C);

        using var fake = new MessageFake
        {
            Ciphertext = [4, 5, 6],
            OnEncryptMessageParams = block =>
            {
                var ccm = UnmanagedMemory.Read<CK_CCM_MESSAGE_PARAMS>(block);
                Assert.NotEqual(IntPtr.Zero, ccm.Mac);
                Assert.Equal(16, (int)(ulong)ccm.MacLen);
                UnmanagedMemory.Write(ccm.Mac, tokenMac);
            },
        };

        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_AES_CCM);
        var p = CkmCcmMessageParams.ForEncrypt(dataLen: 3, new byte[12], macBytes: 16);

        s.MessageEncrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], plaintext: [9, 9, 9]);

        byte[] readBack = new byte[16];
        p.CopyMacTo(readBack);
        Assert.Equal(tokenMac, readBack);
    }

    // === SupportsMechanism (lazy cache) =====================================

    private sealed class MechListFake : SessionTestModule
    {
        public CKR SessionInfoRv = CKR.CKR_OK, MechListRv = CKR.CKR_OK;
        public CKM[] Mechanisms = [CKM.CKM_AES_GCM, CKM.CKM_SHA256];
        public int SessionInfoCalls { get; private set; }
        public int MechListCalls { get; private set; }

        protected override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
        { SessionInfoCalls++; info.SlotId = (NativeCULong)1; return SessionInfoRv; }

        protected override CKR C_GetMechanismList(NativeCULong slotId, NativeBuffer<NativeCULong> mechanismList, ref NativeCULong count)
        {
            MechListCalls++;
            if (mechanismList.IsNull) { count = (NativeCULong)Mechanisms.Length; return MechListRv; }
            for (int i = 0; i < Mechanisms.Length; i++)
                mechanismList.Span[i] = (NativeCULong)(ulong)Mechanisms[i];
            count = (NativeCULong)Mechanisms.Length;
            return MechListRv;
        }
    }

    [Fact]
    public void SupportsMechanism_Present_ReturnsTrue()
    {
        using var fake = new MechListFake();
        using var s = fake.CreateSession(SessionId);
        Assert.True(s.SupportsMechanism(CKM.CKM_AES_GCM));
    }

    [Fact]
    public void SupportsMechanism_Absent_ReturnsFalse()
    {
        using var fake = new MechListFake();
        using var s = fake.CreateSession(SessionId);
        Assert.False(s.SupportsMechanism(CKM.CKM_RSA_PKCS));
    }

    [Fact]
    public void SupportsMechanism_CachesAfterFirstSuccessfulProbe()
    {
        using var fake = new MechListFake();
        using var s = fake.CreateSession(SessionId);

        Assert.True(s.SupportsMechanism(CKM.CKM_AES_GCM));
        Assert.True(s.SupportsMechanism(CKM.CKM_SHA256));
        Assert.False(s.SupportsMechanism(CKM.CKM_RSA_PKCS));

        Assert.Equal(1, fake.SessionInfoCalls); // probe ran exactly once; later calls hit the cache
    }

    [Fact]
    public void SupportsMechanism_GetSessionInfoFails_ReturnsFalse()
    {
        using var fake = new MechListFake { SessionInfoRv = CKR.CKR_SESSION_HANDLE_INVALID };
        using var s = fake.CreateSession(SessionId);
        Assert.False(s.SupportsMechanism(CKM.CKM_AES_GCM));
    }

    [Fact]
    public void SupportsMechanism_EmptyList_ReturnsFalse()
    {
        using var fake = new MechListFake { Mechanisms = [] };
        using var s = fake.CreateSession(SessionId);
        Assert.False(s.SupportsMechanism(CKM.CKM_AES_GCM));
    }

    /// <summary>
    /// A warm cache must not outlive the session. This is the path that answers from memory
    /// without touching the token at all, so nothing else would catch a use-after-dispose here —
    /// it would just keep reporting the mechanism support of a session that no longer exists.
    /// </summary>
    [Fact]
    public void SupportsMechanism_AfterDispose_ThrowsEvenWhenTheAnswerIsCached()
    {
        using var fake = new MechListFake();
        using var s = fake.CreateSession(SessionId);

        Assert.True(s.SupportsMechanism(CKM.CKM_AES_GCM));   // populate the cache while still open
        s.Dispose();

        Assert.Throws<ObjectDisposedException>(() => s.SupportsMechanism(CKM.CKM_AES_GCM));
        Assert.Equal(1, fake.SessionInfoCalls);              // and it did not re-probe on the way out
    }

    // === DigestKey ==========================================================

    private sealed class DigestKeyFake : SessionTestModule
    {
        public CKR InitRv = CKR.CKR_OK, KeyRv = CKR.CKR_OK;
        public byte[] DigestOutput = [0xAA, 0xBB];

        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => InitRv;
        protected override CKR C_DigestKey(NativeCULong session, NativeCULong key) => KeyRv;
        protected override CKR C_DigestFinal(NativeCULong session, NativeBuffer<byte> digest, ref NativeCULong digestLen)
        {
            if (digest.IsNull) { digestLen = (NativeCULong)DigestOutput.Length; return CKR.CKR_OK; }
            DigestOutput.AsSpan(0, DigestOutput.Length).CopyTo(digest.Span);
            digestLen = (NativeCULong)DigestOutput.Length;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void DigestKey_Ok_ReturnsDigest()
    {
        using var fake = new DigestKeyFake { DigestOutput = [1, 2, 3] };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.Equal(new byte[] { 1, 2, 3 }, s.DigestKey(mech, new ObjectHandle(1)));
    }

    [Fact]
    public void DigestKey_DigestKeyError_Throws()
    {
        using var fake = new DigestKeyFake { KeyRv = CKR.CKR_KEY_INDIGESTIBLE };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.DigestKey(mech, new ObjectHandle(1)));
    }

    [Fact]
    public void DigestKey_InitError_Throws()
    {
        using var fake = new DigestKeyFake { InitRv = CKR.CKR_MECHANISM_INVALID };
        using var s = fake.CreateSession(SessionId);
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.DigestKey(mech, new ObjectHandle(1)));
    }
}
