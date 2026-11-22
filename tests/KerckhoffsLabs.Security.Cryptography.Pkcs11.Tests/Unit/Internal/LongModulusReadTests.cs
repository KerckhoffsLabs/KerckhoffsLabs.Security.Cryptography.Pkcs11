using System.Runtime.InteropServices;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

/// <summary>
/// An RSA key's modulus is read into a buffer of exactly the length the module reported, never a guess: NSS softoken's
/// <c>NSC_GetAttributeValue</c> copies the whole value whatever <c>ulValueLen</c> says, so a 2048-byte RSA-16384 modulus
/// copied into a smaller buffer would corrupt the caller's stack. The fake copies the same way, and records, instead of
/// doing it, any copy that would have run past the buffer.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class LongModulusReadTests
{
    private static readonly ObjectHandle Key = new(5UL);

    private sealed class NssLikeRsaModule(int modulusBytes) : SessionTestModule
    {
        public int AttributeCalls { get; private set; }

        /// <summary>Copies that would have written past the caller's buffer, as NSS would have made them.</summary>
        public int Overruns { get; private set; }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            AttributeCalls++;
            CKR rv = CKR.CKR_OK;
            for (int i = 0; i < template.Length; i++)
            {
                switch ((CKA)(ulong)template[i].type)
                {
                    case CKA.CKA_KEY_TYPE:
                        if (template[i].value != IntPtr.Zero)
                            Marshal.WriteInt64(template[i].value, (long)(ulong)CKK.CKK_RSA);
                        template[i].valueLen = (NativeCULong)8UL;
                        break;
                    case CKA.CKA_MODULUS:
                        if (template[i].value != IntPtr.Zero)
                        {
                            // NSS: PORT_Memcpy(pValue, value, valueLength), whatever ulValueLen held.
                            if ((ulong)template[i].valueLen < (ulong)modulusBytes)
                                Overruns++;
                            else
                                WriteModulus(template[i].value);
                        }
                        template[i].valueLen = (NativeCULong)(ulong)modulusBytes;
                        break;
                    default:
                        template[i].valueLen = NativeCULong.MaxValue;
                        rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                }
            }
            return rv;
        }

        // The top bit set, so the modulus is exactly modulusBytes * 8 bits long.
        private void WriteModulus(IntPtr buffer)
        {
            Marshal.WriteByte(buffer, 0x80);
            for (int b = 1; b < modulusBytes; b++)
                Marshal.WriteByte(buffer, b, 0x01);
        }
    }

    [Theory]
    [InlineData(2048, true)]  // RSA-16384: allowed
    [InlineData(512, true)]   // RSA-4096
    [InlineData(128, false)]  // RSA-1024: refused for signing
    public void TheModulus_IsReadAtItsReportedLength_NeverIntoAShorterBuffer(int modulusBytes, bool allowed)
    {
        if (UnmanagedMemory.NativeULongSize != sizeof(ulong))
            Assert.Skip("The fake writes CK_ULONG as 8 bytes (LP64).");
        using var module = new NssLikeRsaModule(modulusBytes);
        using var session = module.CreateSession(policy: CryptoPolicy.Recommended);

        Exception? refused = Record.Exception(() => session.EnforceKeyStrength(Key, KeyStrengthSource.ExistingKey, CryptoOperation.Sign));

        Assert.Equal(0, module.Overruns);
        // The one-call read (the type, and the modulus's length), then the modulus at exactly that length.
        Assert.Equal(2, module.AttributeCalls);
        if (allowed)
        {
            Assert.Null(refused);
        }
        else
        {
            var violation = Assert.IsType<CryptoPolicyViolationException>(refused);
            Assert.Equal(modulusBytes * 8, Assert.IsType<KeyStrengthRequest>(violation.Request).ModulusBits);
        }
    }
}
