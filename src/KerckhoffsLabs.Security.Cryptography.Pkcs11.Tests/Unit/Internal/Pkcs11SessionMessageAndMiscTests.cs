using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native.RawMechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Hermetic coverage for the v3.0 message-based AEAD API (<c>MessageEncrypt</c>/<c>MessageDecrypt</c>),
/// the lazily-cached <c>SupportsMechanism</c> probe, and <c>DigestKey</c>. The message API is only
/// reached through the high-level AEAD algorithm wrappers in the Integration suite, so the
/// session-level length-probe and finalize paths are pinned here through the
/// <see cref="ILowLevelPkcs11Library"/> seam.
/// </summary>
public sealed class Pkcs11SessionMessageAndMiscTests
{
    private const ulong SessionId = 11;

    // === Message AEAD =======================================================

    private sealed class MessageFake : FakeLowLevelPkcs11Library
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

        public override CKR C_MessageEncryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        public override CKR C_MessageEncryptFinal(NativeCULong session) { EncryptFinalCalls++; return CKR.CKR_OK; }
        public override CKR C_MessageDecryptInit(NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        public override CKR C_MessageDecryptFinal(NativeCULong session) { DecryptFinalCalls++; return CKR.CKR_OK; }

        public override CKR C_EncryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] plaintext, NativeCULong plaintextLen, byte[] ciphertext, ref NativeCULong ciphertextLen)
        {
            if (ciphertext is null) { ciphertextLen = (NativeCULong)Ciphertext.Length; return EncMsgRv; }
            OnEncryptMessageParams?.Invoke(parameter);
            Array.Copy(Ciphertext, ciphertext, Ciphertext.Length);
            ciphertextLen = (NativeCULong)Ciphertext.Length;
            return EncMsgRv;
        }

        public override CKR C_DecryptMessage(NativeCULong session, IntPtr parameter, NativeCULong parameterLen, byte[] associatedData, NativeCULong associatedDataLen, byte[] ciphertext, NativeCULong ciphertextLen, byte[] plaintext, ref NativeCULong plaintextLen)
        {
            if (plaintext is null) { plaintextLen = (NativeCULong)Plaintext.Length; return DecMsgRv; }
            OnDecryptMessageParams?.Invoke(parameter);
            Array.Copy(Plaintext, plaintext, Plaintext.Length);
            plaintextLen = (NativeCULong)Plaintext.Length;
            return DecMsgRv;
        }
    }

    private static Pkcs11Session NewSession(FakeLowLevelPkcs11Library fake) => new(fake, SessionId);

    [Fact]
    public void MessageEncrypt_Ok_ReturnsCiphertext_AndFinalizes()
    {
        var fake = new MessageFake { Ciphertext = [1, 2, 3, 4] };
        var s = NewSession(fake);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

        byte[] ct = s.MessageEncrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], plaintext: [9, 9, 9]);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, ct);
        Assert.Equal(1, fake.EncryptFinalCalls); // finalized even on the success path
    }

    [Fact]
    public void MessageEncrypt_Error_ThrowsAndFinalizes()
    {
        var fake = new MessageFake { EncMsgRv = CKR.CKR_DEVICE_ERROR };
        var s = NewSession(fake);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForEncrypt(new byte[12], tagBytes: 16);

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            s.MessageEncrypt(mech, new ObjectHandle(1), p, associatedData: [], plaintext: [1]));
        Assert.Equal(1, fake.EncryptFinalCalls); // finalize runs on the exception unwind
    }

    [Fact]
    public void MessageDecrypt_Ok_ReturnsPlaintext_AndFinalizes()
    {
        var fake = new MessageFake { Plaintext = [7, 7, 7] };
        var s = NewSession(fake);
        var mech = new Mechanism(CKM.CKM_AES_GCM);
        var p = CkmGcmMessageParams.ForDecrypt(new byte[12], new byte[16]);

        byte[] pt = s.MessageDecrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], ciphertext: [1, 2, 3]);

        Assert.Equal(new byte[] { 7, 7, 7 }, pt);
        Assert.Equal(1, fake.DecryptFinalCalls);
    }

    [Fact]
    public void MessageDecrypt_TagFailure_Throws()
    {
        var fake = new MessageFake { DecMsgRv = CKR.CKR_AEAD_DECRYPT_FAILED };
        var s = NewSession(fake);
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

        var fake = new MessageFake
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

        var s = NewSession(fake);
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
        var fake = new MessageFake
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

        var s = NewSession(fake);
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

        var fake = new MessageFake
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

        var s = NewSession(fake);
        var mech = new Mechanism(CKM.CKM_AES_CCM);
        var p = CkmCcmMessageParams.ForEncrypt(dataLen: 3, new byte[12], macBytes: 16);

        s.MessageEncrypt(mech, new ObjectHandle(1), p, associatedData: [0xAA], plaintext: [9, 9, 9]);

        byte[] readBack = new byte[16];
        p.CopyMacTo(readBack);
        Assert.Equal(tokenMac, readBack);
    }

    // === SupportsMechanism (lazy cache) =====================================

    private sealed class MechListFake : FakeLowLevelPkcs11Library
    {
        public CKR SessionInfoRv = CKR.CKR_OK, MechListRv = CKR.CKR_OK;
        public CKM[] Mechanisms = [CKM.CKM_AES_GCM, CKM.CKM_SHA256];
        public int SessionInfoCalls { get; private set; }
        public int MechListCalls { get; private set; }

        public override CKR C_GetSessionInfo(NativeCULong session, ref CK_SESSION_INFO info)
        { SessionInfoCalls++; info.SlotId = (NativeCULong)1; return SessionInfoRv; }

        public override CKR C_GetMechanismList(NativeCULong slotId, CKM[]? mechanismList, ref NativeCULong count)
        {
            MechListCalls++;
            if (mechanismList is null) { count = (NativeCULong)Mechanisms.Length; return MechListRv; }
            for (int i = 0; i < Mechanisms.Length; i++)
                mechanismList[i] = Mechanisms[i];
            count = (NativeCULong)Mechanisms.Length;
            return MechListRv;
        }
    }

    [Fact]
    public void SupportsMechanism_Present_ReturnsTrue()
    {
        var s = NewSession(new MechListFake());
        Assert.True(s.SupportsMechanism(CKM.CKM_AES_GCM));
    }

    [Fact]
    public void SupportsMechanism_Absent_ReturnsFalse()
    {
        var s = NewSession(new MechListFake());
        Assert.False(s.SupportsMechanism(CKM.CKM_RSA_PKCS));
    }

    [Fact]
    public void SupportsMechanism_CachesAfterFirstSuccessfulProbe()
    {
        var fake = new MechListFake();
        var s = NewSession(fake);

        Assert.True(s.SupportsMechanism(CKM.CKM_AES_GCM));
        Assert.True(s.SupportsMechanism(CKM.CKM_SHA256));
        Assert.False(s.SupportsMechanism(CKM.CKM_RSA_PKCS));

        Assert.Equal(1, fake.SessionInfoCalls); // probe ran exactly once; later calls hit the cache
    }

    [Fact]
    public void SupportsMechanism_GetSessionInfoFails_ReturnsFalse()
    {
        var s = NewSession(new MechListFake { SessionInfoRv = CKR.CKR_SESSION_HANDLE_INVALID });
        Assert.False(s.SupportsMechanism(CKM.CKM_AES_GCM));
    }

    [Fact]
    public void SupportsMechanism_EmptyList_ReturnsFalse()
    {
        var s = NewSession(new MechListFake { Mechanisms = [] });
        Assert.False(s.SupportsMechanism(CKM.CKM_AES_GCM));
    }

    // === DigestKey ==========================================================

    private sealed class DigestKeyFake : FakeLowLevelPkcs11Library
    {
        public CKR InitRv = CKR.CKR_OK, KeyRv = CKR.CKR_OK;
        public byte[] DigestOutput = [0xAA, 0xBB];

        public override CKR C_DigestInit(NativeCULong session, ref CK_MECHANISM mechanism) => InitRv;
        public override CKR C_DigestKey(NativeCULong session, NativeCULong key) => KeyRv;
        public override CKR C_DigestFinal(NativeCULong session, byte[]? digest, ref NativeCULong digestLen)
        {
            if (digest is null) { digestLen = (NativeCULong)DigestOutput.Length; return CKR.CKR_OK; }
            Array.Copy(DigestOutput, digest, DigestOutput.Length);
            digestLen = (NativeCULong)DigestOutput.Length;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void DigestKey_Ok_ReturnsDigest()
    {
        var s = NewSession(new DigestKeyFake { DigestOutput = [1, 2, 3] });
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.Equal(new byte[] { 1, 2, 3 }, s.DigestKey(mech, new ObjectHandle(1)));
    }

    [Fact]
    public void DigestKey_DigestKeyError_Throws()
    {
        var s = NewSession(new DigestKeyFake { KeyRv = CKR.CKR_KEY_INDIGESTIBLE });
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.DigestKey(mech, new ObjectHandle(1)));
    }

    [Fact]
    public void DigestKey_InitError_Throws()
    {
        var s = NewSession(new DigestKeyFake { InitRv = CKR.CKR_MECHANISM_INVALID });
        var mech = new Mechanism(CKM.CKM_SHA256);
        Assert.ThrowsAny<Pkcs11Exception>(() => s.DigestKey(mech, new ObjectHandle(1)));
    }
}
