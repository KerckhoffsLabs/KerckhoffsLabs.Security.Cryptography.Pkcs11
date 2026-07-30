using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Regression: a conformant token may return <c>CKR_BUFFER_TOO_SMALL</c> from the
/// two-call length probe (it has still populated the length output, per PKCS#11 v3.2 §5.2).
/// <c>EncapsulateKey</c> must treat that as a successful probe, allocate, and make the real
/// call — not throw. This is exercised through the <see cref="ILowLevelPkcs11Library"/> seam
/// because pkcs11-mock/SoftHSM return <c>CKR_OK</c> from the probe and never hit this branch.
/// </summary>
public sealed class EncapsulateKeyBufferProbeTests
{
    /// <summary>Fake whose C_EncapsulateKey probe returns CKR_BUFFER_TOO_SMALL, then succeeds.</summary>
    private sealed class BufferTooSmallProbeFake : FakeLowLevelPkcs11Library
    {
        public int Calls { get; private set; }
        public const int CiphertextSize = 16;

        public override CKR C_EncapsulateKey(
            NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey,
            CK_ATTRIBUTE[] template, NativeCULong attributeCount,
            byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
        {
            Calls++;

            // First (probe) call: the high-level wrapper passes a null buffer. A conformant
            // token may signal "I populated the length, your buffer was inadequate".
            if (ciphertext is null)
            {
                ciphertextLen = (NativeCULong)CiphertextSize;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }

            // Second (real) call: fill the buffer + hand back a shared-key handle.
            for (int i = 0; i < CiphertextSize && i < ciphertext.Length; i++)
                ciphertext[i] = (byte)(i + 1);
            ciphertextLen = (NativeCULong)CiphertextSize;
            derivedKey = (NativeCULong)42UL;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void EncapsulateKey_ProbeReturnsBufferTooSmall_SucceedsWithoutThrowing()
    {
        var fake = new BufferTooSmallProbeFake();
        var session = new Pkcs11Session(fake, sessionId: 1);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_ML_KEM);

            var (ciphertext, sharedKey) = session.EncapsulateKey(
                mechanism, new ObjectHandle(2), []);

            Assert.Equal(BufferTooSmallProbeFake.CiphertextSize, ciphertext.Length);
            Assert.Equal(2, fake.Calls); // probe (BUFFER_TOO_SMALL) + real call
            Assert.Equal(42UL, sharedKey.ObjectId);
        }
        finally
        {
            session.CloseSession();
        }
    }

    /// <summary>
    /// Models SoftHSM's <c>C_EncapsulateKey</c>: it only writes <c>*pulCipherTextLen</c> when handed a
    /// non-null buffer, so a NULL-buffer length probe leaves the length at 0 — yet each call still runs a
    /// full, side-effectful encapsulation (a fresh shared-secret handle). The two-call probe therefore
    /// cannot work against it; the caller must pass a pre-sized buffer via <c>expectedCiphertextLen</c>.
    /// </summary>
    private sealed class SoftHsmLikeFake : FakeLowLevelPkcs11Library
    {
        public int Calls { get; private set; }
        public const int CiphertextSize = 1088; // ML-KEM-768

        public override CKR C_EncapsulateKey(
            NativeCULong session, ref CK_MECHANISM mechanism, NativeCULong publicKey,
            CK_ATTRIBUTE[] template, NativeCULong attributeCount,
            byte[] ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong derivedKey)
        {
            Calls++;
            derivedKey = (NativeCULong)42UL; // side-effect on every call, even the would-be "probe"

            // SoftHSM ignores a null buffer entirely: it does not populate the length.
            if (ciphertext is null)
                return CKR.CKR_OK;

            if (ciphertext.Length < CiphertextSize)
                return CKR.CKR_BUFFER_TOO_SMALL; // note: length is NOT updated (matches SoftHSM)

            for (int i = 0; i < CiphertextSize; i++)
                ciphertext[i] = (byte)((i + 1) & 0xFF);
            ciphertextLen = (NativeCULong)CiphertextSize;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void EncapsulateKey_WithExpectedLength_SkipsProbe_SingleCall()
    {
        var fake = new SoftHsmLikeFake();
        var session = new Pkcs11Session(fake, sessionId: 1);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_ML_KEM);

            var (ciphertext, sharedKey) = session.EncapsulateKey(
                mechanism, new ObjectHandle(2), [], SoftHsmLikeFake.CiphertextSize);

            Assert.Equal(SoftHsmLikeFake.CiphertextSize, ciphertext.Length);
            Assert.Equal(1, fake.Calls); // pre-sized buffer => one call, no probe
            Assert.Equal(42UL, sharedKey.ObjectId);
        }
        finally
        {
            session.CloseSession();
        }
    }

    [Fact]
    public void EncapsulateKey_NoExpectedLength_AgainstNonProbingToken_Throws()
    {
        // Without the size hint the two-call probe is used; a SoftHSM-like token leaves the length at 0,
        // so the real call gets an empty buffer and CKR_BUFFER_TOO_SMALL — demonstrating why the hint
        // path exists. (The library's ML-KEM surface always supplies the hint.)
        var fake = new SoftHsmLikeFake();
        var session = new Pkcs11Session(fake, sessionId: 1);
        try
        {
            var mechanism = new Mechanism(CKM.CKM_ML_KEM);

            Assert.ThrowsAny<Pkcs11Exception>(() =>
                session.EncapsulateKey(mechanism, new ObjectHandle(2), []));
        }
        finally
        {
            session.CloseSession();
        }
    }
}
