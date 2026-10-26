using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// The <c>C_*Final</c> of every stream transform gets a buffer of at least the update size and a block,
/// whatever length the module reports for it. PKCS#11 v3.2 §5.2 lets a length query over-report but not
/// under-report; Kryoptic's <c>CKM_AES_CBC_PAD</c> answers 0 while its last block is still held back, and a
/// final into an empty buffer fails and ends the operation. Driven through a fake that does the same.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class StreamFinalLengthTests
{
    private const ulong SessionId = 29;
    private static readonly ObjectHandle Key = new(2);
    private static readonly byte[] Input = [.. Enumerable.Range(1, 40).Select(i => (byte)i)];

    public static TheoryData<string> Transforms => ["Encrypt", "Decrypt", "DecryptVerify", "DecryptDigest", "DigestEncrypt"];

    // The last block comes from the final, whose length query answered 0.
    [Theory]
    [MemberData(nameof(Transforms))]
    public void Final_WhoseLengthQueryUnderReports_ReturnsTheLastBlock(string transform)
    {
        using var fake = new UnderReportingFinalFake(holdBack: 16);

        Assert.Equal(Input, Run(fake, transform, bufferLength: 4));
        Assert.Equal(1, fake.FinalFills);
    }

    // A final that holds back more than the update size and a block is grown until it fits.
    [Theory]
    [MemberData(nameof(Transforms))]
    public void Final_LargerThanTheMargin_GrowsTheBuffer(string transform)
    {
        using var fake = new UnderReportingFinalFake(holdBack: int.MaxValue);

        Assert.Equal(Input, Run(fake, transform, bufferLength: 4));
        Assert.Equal(3, fake.FinalFills); // 16, 32, then 64 bytes
    }

    private static byte[] Run(UnderReportingFinalFake fake, string transform, int bufferLength)
    {
        using var session = fake.CreateSession(SessionId);
        using var source = new MemoryStream(Input);
        using var sink = new MemoryStream();
        Mechanism Aes() => new(CKM.CKM_AES_GCM);
        Mechanism Sha256() => new(CKM.CKM_SHA256);

        switch (transform)
        {
            case "Encrypt":
                session.Encrypt(Aes(), Key, source, sink, bufferLength);
                break;
            case "Decrypt":
                session.Decrypt(Aes(), Key, source, sink, bufferLength);
                break;
            case "DecryptVerify":
                Assert.True(session.DecryptVerify(new Mechanism(CKM.CKM_SHA256_HMAC), new ObjectHandle(3), Aes(), Key, source, sink, signature: new byte[32], bufferLength));
                break;
            case "DecryptDigest":
                session.DecryptDigest(Sha256(), Aes(), Key, source, sink, bufferLength);
                break;
            default:
                session.DigestEncrypt(Sha256(), Aes(), Key, source, sink, bufferLength);
                break;
        }
        return sink.ToArray();
    }

    /// <summary>
    /// An identity transform that holds back the last <c>holdBack</c> bytes of what it has seen until the
    /// final, as a block cipher holds back its last block. The final's length query answers 0; a final into
    /// a buffer too small for what is held back answers <c>CKR_BUFFER_TOO_SMALL</c> and leaves the length as
    /// the caller passed it.
    /// </summary>
    private sealed class UnderReportingFinalFake(int holdBack) : SessionTestModule
    {
        private readonly List<byte> _held = [];

        public int FinalFills { get; private set; }

        protected override CKR C_EncryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DecryptInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_DigestInit(NativeCULong session, CK_MECHANISM mechanism) => CKR.CKR_OK;
        protected override CKR C_VerifyInit(NativeCULong session, CK_MECHANISM mechanism, NativeCULong key) => CKR.CKR_OK;
        protected override CKR C_VerifyFinal(NativeCULong session, ReadOnlySpan<byte> signature) => CKR.CKR_OK;

        protected override CKR C_DigestFinal(NativeCULong session, NativeBuffer<byte> digest, ref NativeCULong digestLen)
        {
            digestLen = (NativeCULong)32UL;
            return CKR.CKR_OK;
        }

        protected override CKR C_EncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen)
            => Update(part, encryptedPart, ref encryptedPartLen);
        protected override CKR C_DecryptUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Update(encryptedPart, part, ref partLen);
        protected override CKR C_DecryptVerifyUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Update(encryptedPart, part, ref partLen);
        protected override CKR C_DecryptDigestUpdate(NativeCULong session, ReadOnlySpan<byte> encryptedPart, NativeBuffer<byte> part, ref NativeCULong partLen)
            => Update(encryptedPart, part, ref partLen);
        protected override CKR C_DigestEncryptUpdate(NativeCULong session, ReadOnlySpan<byte> part, NativeBuffer<byte> encryptedPart, ref NativeCULong encryptedPartLen)
            => Update(part, encryptedPart, ref encryptedPartLen);

        protected override CKR C_EncryptFinal(NativeCULong session, NativeBuffer<byte> lastEncryptedPart, ref NativeCULong lastEncryptedPartLen)
            => Final(lastEncryptedPart, ref lastEncryptedPartLen);
        protected override CKR C_DecryptFinal(NativeCULong session, NativeBuffer<byte> lastPart, ref NativeCULong lastPartLen)
            => Final(lastPart, ref lastPartLen);

        private CKR Update(ReadOnlySpan<byte> input, NativeBuffer<byte> output, ref NativeCULong outputLen)
        {
            _held.AddRange(input);
            int emitted = Math.Max(0, _held.Count - holdBack);
            _held.Take(emitted).ToArray().CopyTo(output.Span);
            _held.RemoveRange(0, emitted);
            outputLen = (NativeCULong)(ulong)emitted;
            return CKR.CKR_OK;
        }

        private CKR Final(NativeBuffer<byte> output, ref NativeCULong outputLen)
        {
            if (output.IsNull)
            {
                outputLen = (NativeCULong)0UL; // under-reports: the held-back bytes are not counted
                return CKR.CKR_OK;
            }

            FinalFills++;
            if (output.Span.Length < _held.Count)
                return CKR.CKR_BUFFER_TOO_SMALL;

            _held.ToArray().CopyTo(output.Span);
            outputLen = (NativeCULong)(ulong)_held.Count;
            _held.Clear();
            return CKR.CKR_OK;
        }
    }
}
