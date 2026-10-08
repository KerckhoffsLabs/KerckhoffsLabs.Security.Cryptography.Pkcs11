using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// Regression: a conformant token may return <c>CKR_BUFFER_TOO_SMALL</c> from the
/// two-call length probe (it has still populated the length output, per PKCS#11 v3.2 §5.2).
/// <c>EncapsulateKey</c> must treat that as a successful probe, allocate, and make the real
/// call — not throw. This is exercised through a <see cref="FakeModule"/> because
/// pkcs11-mock/SoftHSM return <c>CKR_OK</c> from the probe and never hit this branch.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class EncapsulateKeyBufferProbeTests
{
    /// <summary>Fake whose C_EncapsulateKey probe returns CKR_BUFFER_TOO_SMALL, then succeeds.</summary>
    private sealed class BufferTooSmallProbeFake : SessionTestModule
    {
        public new int Calls { get; private set; }
        public const int CiphertextSize = 16;

        protected override CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key)
        {
            Calls++;

            // First (probe) call: the high-level wrapper passes a null buffer. A conformant
            // token may signal "I populated the length, your buffer was inadequate".
            if (ciphertext.IsNull)
            {
                ciphertextLen = (NativeCULong)CiphertextSize;
                return CKR.CKR_BUFFER_TOO_SMALL;
            }

            // Second (real) call: fill the buffer + hand back a shared-key handle.
            for (int i = 0; i < CiphertextSize && i < ciphertext.Span.Length; i++)
                ciphertext.Span[i] = (byte)(i + 1);
            ciphertextLen = (NativeCULong)CiphertextSize;
            key = (NativeCULong)42UL;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void EncapsulateKey_ProbeReturnsBufferTooSmall_SucceedsWithoutThrowing()
    {
        using var fake = new BufferTooSmallProbeFake();
        using var session = fake.CreateSession(sessionId: 1);
        var mechanism = new Mechanism(CKM.CKM_ML_KEM);

        var (ciphertext, sharedKey) = session.EncapsulateKey(
            mechanism, new ObjectHandle(2), []);

        Assert.Equal(BufferTooSmallProbeFake.CiphertextSize, ciphertext.Length);
        Assert.Equal(2, fake.Calls); // probe (BUFFER_TOO_SMALL) + real call
        Assert.Equal(42UL, sharedKey.ObjectId);
    }

    /// <summary>
    /// Models SoftHSM's <c>C_EncapsulateKey</c>: it only writes <c>*pulCipherTextLen</c> when handed a
    /// non-null buffer, so a NULL-buffer length probe leaves the length at 0 — yet each call still runs a
    /// full, side-effectful encapsulation (a fresh shared-secret handle). The two-call probe therefore
    /// cannot work against it; the caller must pass a pre-sized buffer via <c>expectedCiphertextLen</c>.
    /// </summary>
    private sealed class SoftHsmLikeFake : SessionTestModule
    {
        public new int Calls { get; private set; }
        public const int CiphertextSize = 1088; // ML-KEM-768

        protected override CKR C_EncapsulateKey(NativeCULong session, CK_MECHANISM mechanism, NativeCULong publicKey, CK_ATTRIBUTE[] template, NativeBuffer<byte> ciphertext, ref NativeCULong ciphertextLen, ref NativeCULong key)
        {
            // Like SoftHSM, ciphertextLen is left as the caller passed it (the capacity) unless the
            // ciphertext is written.
            Calls++;
            key = (NativeCULong)42UL; // side-effect on every call, even the would-be "probe"

            // SoftHSM ignores an empty (NULL) buffer entirely: it does not populate the length.
            if (ciphertext.IsNull)
                return CKR.CKR_OK;

            if (ciphertext.Span.Length < CiphertextSize)
                return CKR.CKR_BUFFER_TOO_SMALL; // note: length is NOT updated (matches SoftHSM)

            for (int i = 0; i < CiphertextSize; i++)
                ciphertext.Span[i] = (byte)((i + 1) & 0xFF);
            ciphertextLen = (NativeCULong)CiphertextSize;
            return CKR.CKR_OK;
        }
    }

    [Fact]
    public void EncapsulateKey_WithExpectedLength_SkipsProbe_SingleCall()
    {
        using var fake = new SoftHsmLikeFake();
        using var session = fake.CreateSession(sessionId: 1);
        var mechanism = new Mechanism(CKM.CKM_ML_KEM);

        var (ciphertext, sharedKey) = session.EncapsulateKey(
            mechanism, new ObjectHandle(2), [], SoftHsmLikeFake.CiphertextSize);

        Assert.Equal(SoftHsmLikeFake.CiphertextSize, ciphertext.Length);
        Assert.Equal(1, fake.Calls); // pre-sized buffer => one call, no probe
        Assert.Equal(42UL, sharedKey.ObjectId);
    }

    [Fact]
    public void EncapsulateKey_NoExpectedLength_AgainstNonProbingToken_Throws()
    {
        // Without the size hint the two-call probe is used; a SoftHSM-like token reports no size, so
        // the probe fails loudly rather than returning an empty ciphertext for an encapsulation that
        // really happened — demonstrating why the hint path exists. (The library's ML-KEM surface
        // always supplies the hint.)
        using var fake = new SoftHsmLikeFake();
        using var session = fake.CreateSession(sessionId: 1);
        var mechanism = new Mechanism(CKM.CKM_ML_KEM);

        Assert.ThrowsAny<Pkcs11Exception>(() =>
            session.EncapsulateKey(mechanism, new ObjectHandle(2), []));
    }
}
