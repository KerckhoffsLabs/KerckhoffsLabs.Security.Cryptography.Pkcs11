using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.MechanismParams;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// How an existing RSA or EC key's modulus or domain parameters are read to describe its strength: their length in the
/// one call that reads the type, then the value into a buffer of exactly that length, and the generic two-call read
/// when the module left the length unanswered or the value no longer fits. Every way the value can be missing
/// describes the key as not reporting it, which an inspecting policy refuses; a device error stops the operation.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class KeyStrengthValueReadTests
{
    private static readonly ObjectHandle Key = new(5UL);

    private static readonly byte[] P256 = Pkcs11ECCurve.NamedCurves.NistP256.GetEcParams();

    /// <summary>
    /// How the module answers a call after the first: a return value, and the length it reports. A
    /// <see langword="null"/> return value answers as a well-behaved module would.
    /// </summary>
    private readonly record struct Answer(CKR? Rv = null, ulong? ReportedLength = null)
    {
        public static Answer AsTheModuleWould => default;
    }

    /// <summary>
    /// One key: its type, and the byte-array attributes it holds. The first call is the one-call read of the type, the
    /// size attributes and the lengths; every later call is answered from <see cref="Later"/> in order, then as a
    /// well-behaved module would.
    /// </summary>
    private sealed class ValueFake : SessionTestModule
    {
        public CKK KeyType { get; set; } = CKK.CKK_EC;

        public Dictionary<CKA, byte[]> Values { get; } = [];

        /// <summary>Leaves <c>CKA_KEY_TYPE</c> as it was handed out in the first call, which marks it unanswered.</summary>
        public bool LeavesTheKeyTypeAlone { get; set; }

        /// <summary>Leaves the modulus and domain-parameter lengths at 0 in the first call, which marks them unanswered.</summary>
        public bool LeavesTheLengthsAlone { get; set; }

        public Queue<Answer> Later { get; } = new();

        public int AttributeCalls { get; private set; }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            AttributeCalls++;
            if (AttributeCalls == 1)
                return AnswerTheOneCall(template);
            if (Later.TryDequeue(out Answer answer) && answer.Rv is { } rv)
            {
                template[0].valueLen = answer.ReportedLength is { } reported ? (NativeCULong)reported : NativeCULong.MaxValue;
                return rv;
            }
            return AnswerOne(ref template[0], answer.ReportedLength);
        }

        private CKR AnswerTheOneCall(Span<CK_ATTRIBUTE> template)
        {
            CKR rv = CKR.CKR_OK;
            for (int i = 0; i < template.Length; i++)
            {
                var type = (CKA)(ulong)template[i].type;
                if (type == CKA.CKA_KEY_TYPE)
                {
                    if (!LeavesTheKeyTypeAlone)
                        WriteUlong(ref template[i], (ulong)KeyType);
                }
                else if (type is CKA.CKA_MODULUS or CKA.CKA_EC_PARAMS && Values.TryGetValue(type, out byte[]? value))
                {
                    if (!LeavesTheLengthsAlone)
                        template[i].valueLen = (NativeCULong)(ulong)value.Length;
                }
                else
                {
                    template[i].valueLen = NativeCULong.MaxValue;
                    rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                }
            }
            return rv;
        }

        // A single attribute, as PKCS#11 v3.2 answers it: the length to a NULL pValue, the value into a buffer that
        // holds it, CKR_BUFFER_TOO_SMALL otherwise. reportedLength replaces the length written back.
        private CKR AnswerOne(ref CK_ATTRIBUTE attribute, ulong? reportedLength)
        {
            var type = (CKA)(ulong)attribute.type;
            if (type == CKA.CKA_KEY_TYPE)
            {
                WriteUlong(ref attribute, (ulong)KeyType);
                return CKR.CKR_OK;
            }
            if (!Values.TryGetValue(type, out byte[]? value))
            {
                attribute.valueLen = NativeCULong.MaxValue;
                return CKR.CKR_ATTRIBUTE_TYPE_INVALID;
            }
            if (attribute.value != IntPtr.Zero)
            {
                if ((ulong)attribute.valueLen < (ulong)value.Length)
                {
                    attribute.valueLen = NativeCULong.MaxValue;
                    return CKR.CKR_BUFFER_TOO_SMALL;
                }
                UnmanagedMemory.Write(attribute.value, value);
            }
            attribute.valueLen = (NativeCULong)(reportedLength ?? (ulong)value.Length);
            return CKR.CKR_OK;
        }

        private static void WriteUlong(ref CK_ATTRIBUTE attribute, ulong value)
        {
            using var encoded = new ObjectAttribute(CKA.CKA_KEY_TYPE, value);
            byte[] bytes = encoded.GetValueAsByteArray();
            if (attribute.value != IntPtr.Zero)
                UnmanagedMemory.Write(attribute.value, bytes);
            attribute.valueLen = (NativeCULong)(ulong)bytes.Length;
        }
    }

    /// <summary>Recommended, but inspecting keys and refusing every one, so each test sees how the key was described.</summary>
    private static ComposedCryptoPolicy RefuseEveryKey() =>
        CryptoPolicy.Recommended.ToBuilder("T")
            .WithKeyStrengthRule(KeyStrengthRule.FromDelegate(_ => PolicyDecision.Deny("Judged."), "refuse every key"))
            .Build();

    private static void UseTheKey(Pkcs11SessionCore session)
        => session.Encrypt(new Mechanism(CKM.CKM_AES_GCM, new CkmAesGcmParams(new byte[12], [], 128)), Key, new byte[16].AsSpan());

    private static KeyStrengthRequest Described(ValueFake fake)
    {
        using var session = fake.CreateSession(policy: RefuseEveryKey());
        return Assert.IsType<KeyStrengthRequest>(Assert.Throws<CryptoPolicyViolationException>(() => UseTheKey(session)).Request);
    }

    private static ValueFake EcKey(byte[]? ecParams = null)
    {
        var fake = new ValueFake();
        fake.Values[CKA.CKA_EC_PARAMS] = ecParams ?? P256;
        return fake;
    }

    // The control: the length in the one call, then the value at exactly that length.
    [Fact]
    public void EcKey_IsDescribedByItsCurve_InTwoCalls()
    {
        using ValueFake fake = EcKey();

        Assert.Equal(Pkcs11ECCurve.NamedCurves.NistP256, Described(fake).Curve);
        Assert.Equal(2, fake.AttributeCalls);
    }

    // A modulus of zero bytes only has no bit length: the key is described as not reporting one, never as a 0-bit key.
    [Fact]
    public void RsaModulusOfZeroBytesOnly_IsDescribedAsUnreported()
    {
        using var fake = new ValueFake { KeyType = CKK.CKK_RSA };
        fake.Values[CKA.CKA_MODULUS] = new byte[256];

        KeyStrengthRequest request = Described(fake);

        Assert.Equal(CKK.CKK_RSA, request.KeyType);
        Assert.Null(request.ModulusBits);
    }

    // Leading zero bytes are not counted: a 2048-bit modulus stored in 257 bytes is 2048 bits.
    [Fact]
    public void RsaModulusWithALeadingZeroByte_IsMeasuredWithoutIt()
    {
        using var fake = new ValueFake { KeyType = CKK.CKK_RSA };
        byte[] modulus = new byte[257];
        modulus[1] = 0x80;
        fake.Values[CKA.CKA_MODULUS] = modulus;

        Assert.Equal(2048, Described(fake).ModulusBits);
    }

    // An EC key the token reports no domain parameters for: one call, and no curve.
    [Fact]
    public void EcKeyWithoutDomainParameters_IsDescribedWithoutACurve_InOneCall()
    {
        using var fake = new ValueFake();

        KeyStrengthRequest request = Described(fake);

        Assert.Equal(CKK.CKK_EC, request.KeyType);
        Assert.Null(request.Curve);
        Assert.Equal(1, fake.AttributeCalls);
    }

    // Explicit domain parameters (an ECParameters SEQUENCE), or bytes that are no DER at all, name no curve.
    [Theory]
    [InlineData(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 })]
    [InlineData(new byte[] { 0xFF })]
    public void DomainParametersThatNameNoCurve_AreDescribedWithoutACurve(byte[] ecParams)
    {
        using ValueFake fake = EcKey(ecParams);

        Assert.Null(Described(fake).Curve);
    }

    // A module that left the length unanswered (still 0) is asked again through the generic two-call read.
    [Fact]
    public void LengthLeftUnanswered_IsReadAgain_ThroughTheGenericRead()
    {
        using ValueFake fake = EcKey();
        fake.LeavesTheLengthsAlone = true;

        Assert.Equal(Pkcs11ECCurve.NamedCurves.NistP256, Described(fake).Curve);
        Assert.Equal(3, fake.AttributeCalls);
    }

    public enum GenericReadFailure
    {
        /// <summary>The value is sensitive: CKR_ATTRIBUTE_SENSITIVE with the -1 length.</summary>
        Sensitive,

        /// <summary>The handle is gone by the time the value is read again.</summary>
        ObjectHandleInvalid,

        /// <summary>The handle is gone, answered as a key handle.</summary>
        KeyHandleInvalid,

        /// <summary>The value grew between the length and the value: reported longer than the buffer it was given.</summary>
        GrewPastTheBuffer,
    }

    // However the generic read fails to bring the value back, the key is described without it, never thrown as a
    // token error: the policy then refuses the unreported curve.
    [Theory]
    [InlineData(GenericReadFailure.Sensitive)]
    [InlineData(GenericReadFailure.ObjectHandleInvalid)]
    [InlineData(GenericReadFailure.KeyHandleInvalid)]
    [InlineData(GenericReadFailure.GrewPastTheBuffer)]
    public void GenericReadThatBringsNoValue_IsDescribedWithoutACurve(GenericReadFailure failure)
    {
        using ValueFake fake = EcKey();
        fake.LeavesTheLengthsAlone = true;
        switch (failure)
        {
            case GenericReadFailure.Sensitive:
                // Both calls of the generic read: the length, then the value.
                fake.Later.Enqueue(new Answer(CKR.CKR_ATTRIBUTE_SENSITIVE));
                fake.Later.Enqueue(new Answer(CKR.CKR_ATTRIBUTE_SENSITIVE));
                break;
            case GenericReadFailure.ObjectHandleInvalid:
                fake.Later.Enqueue(new Answer(CKR.CKR_OBJECT_HANDLE_INVALID));
                break;
            case GenericReadFailure.KeyHandleInvalid:
                fake.Later.Enqueue(new Answer(CKR.CKR_KEY_HANDLE_INVALID));
                break;
            case GenericReadFailure.GrewPastTheBuffer:
                fake.Later.Enqueue(Answer.AsTheModuleWould);
                fake.Later.Enqueue(new Answer(ReportedLength: (ulong)P256.Length + 1));
                break;
        }

        KeyStrengthRequest request = Described(fake);

        Assert.Equal(CKK.CKK_EC, request.KeyType);
        Assert.Null(request.Curve);
    }

    // The value outgrew the length the one call reported (CKR_BUFFER_TOO_SMALL into the exact buffer): it is read again
    // through the generic read, which sizes its buffer from a fresh length.
    [Fact]
    public void ValueThatOutgrewItsLength_IsReadAgain_ThroughTheGenericRead()
    {
        using ValueFake fake = EcKey();
        fake.Later.Enqueue(new Answer(CKR.CKR_BUFFER_TOO_SMALL));

        Assert.Equal(Pkcs11ECCurve.NamedCurves.NistP256, Described(fake).Curve);
        Assert.Equal(4, fake.AttributeCalls);
    }

    public static TheoryData<CKR?, ulong?> ExactReadsWithoutAValue() => new()
    {
        // CKR_OK, but a value shorter than the length the one call reported: not trusted, and not read again.
        { null, 1UL },
        { CKR.CKR_ATTRIBUTE_SENSITIVE, null },
        { CKR.CKR_ATTRIBUTE_TYPE_INVALID, null },
        { CKR.CKR_OBJECT_HANDLE_INVALID, null },
        { CKR.CKR_KEY_HANDLE_INVALID, null },
    };

    // An exact read that brings back no value describes the key without it, in the two calls already made.
    [Theory]
    [MemberData(nameof(ExactReadsWithoutAValue))]
    public void ExactReadWithoutAValue_IsDescribedWithoutACurve(CKR? rv, ulong? reportedLength)
    {
        using ValueFake fake = EcKey();
        fake.Later.Enqueue(new Answer(rv, reportedLength));

        Assert.Null(Described(fake).Curve);
        Assert.Equal(2, fake.AttributeCalls);
    }

    // A device or session failure of the exact read is the token's error, not the key's: it propagates, and the
    // operation it guards never reaches the token.
    [Theory]
    [InlineData(CKR.CKR_DEVICE_ERROR)]
    [InlineData(CKR.CKR_SESSION_HANDLE_INVALID)]
    public void ExactReadThatFails_Propagates(CKR failure)
    {
        using ValueFake fake = EcKey();
        fake.Later.Enqueue(new Answer(failure));
        using var session = fake.CreateSession(policy: RefuseEveryKey());

        Pkcs11Exception ex = Assert.ThrowsAny<Pkcs11Exception>(() => UseTheKey(session));

        Assert.Equal(failure, ex.ReturnValue);
    }

    // A key type the module left unanswered is asked for alone; that read failing with a device error propagates too.
    [Fact]
    public void KeyTypeReadAgain_ThatFails_Propagates()
    {
        using var fake = new ValueFake { LeavesTheKeyTypeAlone = true };
        fake.Later.Enqueue(new Answer(CKR.CKR_DEVICE_ERROR));
        using var session = fake.CreateSession(policy: RefuseEveryKey());

        Pkcs11Exception ex = Assert.ThrowsAny<Pkcs11Exception>(() => UseTheKey(session));

        Assert.Equal(CKR.CKR_DEVICE_ERROR, ex.ReturnValue);
        Assert.Equal(2, fake.AttributeCalls);
    }

    // Asked again alone, a key type the module answers as unavailable, or for a handle it no longer knows, describes
    // the key without a type, which the policy refuses; none of these is thrown as the token's error.
    [Theory]
    [InlineData(CKR.CKR_ATTRIBUTE_SENSITIVE)]
    [InlineData(CKR.CKR_ATTRIBUTE_TYPE_INVALID)]
    [InlineData(CKR.CKR_BUFFER_TOO_SMALL)]
    [InlineData(CKR.CKR_OBJECT_HANDLE_INVALID)]
    [InlineData(CKR.CKR_KEY_HANDLE_INVALID)]
    public void KeyTypeReadAgain_AnsweredWithoutAValue_IsDescribedWithoutAType(CKR rv)
    {
        using var fake = new ValueFake { LeavesTheKeyTypeAlone = true };
        fake.Later.Enqueue(new Answer(rv));

        Assert.Null(Described(fake).KeyType);
        Assert.Equal(2, fake.AttributeCalls);
    }

    // The control for the tests above: asked again alone, the key type is the one the key is judged as.
    [Fact]
    public void KeyTypeLeftUnanswered_IsReadAgainAlone()
    {
        using var fake = new ValueFake { LeavesTheKeyTypeAlone = true };

        Assert.Equal(CKK.CKK_EC, Described(fake).KeyType);
        Assert.Equal(2, fake.AttributeCalls);
    }
}
