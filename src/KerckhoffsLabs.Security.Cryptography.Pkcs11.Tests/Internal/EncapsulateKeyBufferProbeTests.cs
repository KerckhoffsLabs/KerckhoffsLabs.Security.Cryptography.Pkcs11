using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fakes;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Internal;

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
            using var mechanism = new Mechanism(CKM.CKM_ML_KEM);

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
}
