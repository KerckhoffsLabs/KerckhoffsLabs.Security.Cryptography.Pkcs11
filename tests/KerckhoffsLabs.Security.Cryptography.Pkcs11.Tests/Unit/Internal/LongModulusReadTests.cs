using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// An RSA modulus longer than the one-call read's buffer (RSA-16384, 2048 bytes) is read again on its own, and judged,
/// however the module reports it too long: <c>CK_UNAVAILABLE_INFORMATION</c> under <c>CKR_BUFFER_TOO_SMALL</c>; the
/// same mark under <c>CKR_ATTRIBUTE_TYPE_INVALID</c>, because the call also asked for attributes an RSA key lacks and the
/// module returns that code first (SoftHSM2's <c>P11Object::loadTemplate</c> does); or its real length.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class LongModulusReadTests
{
    private static readonly ObjectHandle Key = new(5UL);

    /// <summary>How a module reports a value too long for its buffer.</summary>
    public enum TooLong
    {
        /// <summary><c>CK_UNAVAILABLE_INFORMATION</c>, and <c>CKR_BUFFER_TOO_SMALL</c> wins the return value.</summary>
        BufferTooSmallFirst,

        /// <summary><c>CK_UNAVAILABLE_INFORMATION</c>, and <c>CKR_ATTRIBUTE_TYPE_INVALID</c> wins: SoftHSM2.</summary>
        TypeInvalidFirst,

        /// <summary>The value's real length, and <c>CKR_BUFFER_TOO_SMALL</c> wins.</summary>
        RealLength,
    }

    private sealed class RsaKeyModule(int modulusBytes, TooLong report) : SessionTestModule
    {
        public int AttributeCalls { get; private set; }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            AttributeCalls++;
            bool invalid = false, tooSmall = false;
            for (int i = 0; i < template.Length; i++)
            {
                switch ((CKA)(ulong)template[i].type)
                {
                    case CKA.CKA_KEY_TYPE:
                        Marshal.WriteInt64(template[i].value, (long)(ulong)CKK.CKK_RSA);
                        template[i].valueLen = (NativeCULong)8UL;
                        break;
                    case CKA.CKA_MODULUS when template[i].value == IntPtr.Zero:
                        template[i].valueLen = (NativeCULong)(ulong)modulusBytes;
                        break;
                    case CKA.CKA_MODULUS when (ulong)template[i].valueLen < (ulong)modulusBytes:
                        template[i].valueLen = report == TooLong.RealLength ? (NativeCULong)(ulong)modulusBytes : NativeCULong.MaxValue;
                        tooSmall = true;
                        break;
                    case CKA.CKA_MODULUS:
                        // The top bit set, so the modulus is exactly modulusBytes * 8 bits long.
                        Marshal.WriteByte(template[i].value, 0x80);
                        for (int b = 1; b < modulusBytes; b++)
                            Marshal.WriteByte(template[i].value, b, 0x01);
                        template[i].valueLen = (NativeCULong)(ulong)modulusBytes;
                        break;
                    default:
                        template[i].valueLen = NativeCULong.MaxValue;
                        invalid = true;
                        break;
                }
            }
            if (report == TooLong.TypeInvalidFirst)
                return invalid ? CKR.CKR_ATTRIBUTE_TYPE_INVALID : tooSmall ? CKR.CKR_BUFFER_TOO_SMALL : CKR.CKR_OK;
            return tooSmall ? CKR.CKR_BUFFER_TOO_SMALL : invalid ? CKR.CKR_ATTRIBUTE_TYPE_INVALID : CKR.CKR_OK;
        }
    }

    [Theory]
    [InlineData(TooLong.BufferTooSmallFirst)]
    [InlineData(TooLong.TypeInvalidFirst)]
    [InlineData(TooLong.RealLength)]
    public void AnRsa16384Modulus_IsReadAgainAlone_AndAllowed(TooLong report)
    {
        if (UnmanagedMemory.NativeULongSize != sizeof(ulong))
            Assert.Skip("The fake writes CK_ULONG as 8 bytes (LP64).");
        using var module = new RsaKeyModule(modulusBytes: 2048, report);
        using var session = module.CreateSession(policy: CryptoPolicy.Recommended);

        session.EnforceKeyStrength(Key, KeyStrengthSource.ExistingKey, CryptoOperation.Sign);

        // The one-call read, then the modulus alone through the generic reader (its length, then its value).
        Assert.Equal(3, module.AttributeCalls);
    }

    [Theory]
    [InlineData(TooLong.BufferTooSmallFirst)]
    [InlineData(TooLong.TypeInvalidFirst)]
    [InlineData(TooLong.RealLength)]
    public void AShortModulusReadInOneCall_IsStillJudged(TooLong report)
    {
        if (UnmanagedMemory.NativeULongSize != sizeof(ulong))
            Assert.Skip("The fake writes CK_ULONG as 8 bytes (LP64).");
        using var module = new RsaKeyModule(modulusBytes: 128, report);
        using var session = module.CreateSession(policy: CryptoPolicy.Recommended);

        var refused = Assert.Throws<CryptoPolicyViolationException>(
            () => session.EnforceKeyStrength(Key, KeyStrengthSource.ExistingKey, CryptoOperation.Sign));

        Assert.Equal(1024, Assert.IsType<KeyStrengthRequest>(refused.Request).ModulusBits);
        Assert.Equal(1, module.AttributeCalls);
    }
}
