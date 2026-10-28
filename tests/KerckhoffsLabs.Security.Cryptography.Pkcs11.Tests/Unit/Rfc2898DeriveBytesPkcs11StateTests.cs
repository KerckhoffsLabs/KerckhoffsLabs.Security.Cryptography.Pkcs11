using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

// The obsolete instance constructors build the instances whose state these tests read, ours and the BCL's.
#pragma warning disable KLPKCS11011, SYSLIB0060

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Rfc2898DeriveBytesPkcs11"/>'s state and the failures a token can cause after the derivation
/// itself succeeded. The properties need no PBKDF2 and run on the in-process token, which does not
/// implement it; the read-back failures run on a module that derives a key whose value it then withholds.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Rfc2898DeriveBytesPkcs11StateTests
{
    private static readonly byte[] Password = "password"u8.ToArray();
    private static readonly byte[] Salt = new byte[16];

    // === Properties ========================================================

    [Fact]
    public void IterationCount_ReturnsWhatWasSet()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var kdf = new Rfc2898DeriveBytesPkcs11(session, Password, Salt, 1000, HashAlgorithmName.SHA256);

        Assert.Equal(1000, kdf.IterationCount);
        kdf.IterationCount = 2000;
        Assert.Equal(2000, kdf.IterationCount);
    }

    // As the BCL's setter: zero and negative counts are refused, and the count is left as it was.
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void IterationCount_NonPositive_Throws(int iterations)
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        using var kdf = new Rfc2898DeriveBytesPkcs11(session, Password, Salt, 1000, HashAlgorithmName.SHA256);
        using var bcl = new Rfc2898DeriveBytes(Password, Salt, 1000, HashAlgorithmName.SHA256);

        Assert.Throws<ArgumentOutOfRangeException>(() => bcl.IterationCount = iterations);
        Assert.Throws<ArgumentOutOfRangeException>(() => kdf.IterationCount = iterations);
        Assert.Equal(1000, kdf.IterationCount);
    }

    // The getter hands out a copy, as the BCL's does: changing it changes nothing in the instance.
    [Fact]
    public void Salt_ReturnsACopy()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library);
        byte[] salt = [.. Enumerable.Range(1, 16).Select(i => (byte)i)];
        using var kdf = new Rfc2898DeriveBytesPkcs11(session, Password, salt, 1000, HashAlgorithmName.SHA256);

        byte[] read = kdf.Salt;
        Assert.Equal(salt, read);
        read[0] ^= 0xFF;
        Assert.Equal(salt, kdf.Salt);
    }

    // An empty destination asks for nothing, so the token is not called: the in-process token, which has no
    // PBKDF2, would refuse the mechanism.
    [Fact]
    public void StaticPbkdf2_EmptyDestination_MakesNoTokenCall()
    {
        using var library = ManagedToken.NewLibrary();
        using var session = ManagedToken.OpenSession(library, CryptoPolicy.AllowInsecure);

        Rfc2898DeriveBytesPkcs11.Pbkdf2(session, Password, Salt, Span<byte>.Empty, 1000, HashAlgorithmName.SHA256);
    }

    // === Read-back failures ================================================

    // A token that derives the key but will not hand its value back: the caller learns why, and the key
    // is destroyed.
    [Fact]
    public void Pbkdf2_DerivedValueWithheld_ThrowsAndDestroysTheKey()
    {
        using var module = new WithholdingPbkd2Module();
        using var scope = module.OpenSession();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            Rfc2898DeriveBytesPkcs11.Pbkdf2(scope.Session, Password, Salt, 1000, HashAlgorithmName.SHA256, 32));

        Assert.Contains("CKA_VALUE", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, module.DestroyCalls);
    }

    // When the destroy fails too, the reason the derivation failed is the one reported, not the destroy's.
    [Fact]
    public void Pbkdf2_DerivedValueWithheld_AndDestroyFails_ReportsTheReadFailure()
    {
        using var module = new WithholdingPbkd2Module { DestroyResult = CKR.CKR_DEVICE_ERROR };
        using var scope = module.OpenSession();

        Assert.Throws<InvalidOperationException>(() =>
            Rfc2898DeriveBytesPkcs11.Pbkdf2(scope.Session, Password, Salt, 1000, HashAlgorithmName.SHA256, 32));
        Assert.Equal(1, module.DestroyCalls);
    }

    internal sealed class SessionScope(Pkcs11Session session, Pkcs11Library library) : IDisposable
    {
        public Pkcs11Session Session { get; } = session;

        public void Dispose()
        {
            Session.Dispose();
            library.Dispose();
        }
    }

    /// <summary>
    /// Derives every <c>CKM_PKCS5_PBKD2</c> key as handle 1, a generic secret whose class and key type it
    /// reports and whose <c>CKA_VALUE</c> it withholds as sensitive. Reports a v3.0 module and slot from a
    /// maker the PBKDF2 layout detection does not single out.
    /// </summary>
    private sealed class WithholdingPbkd2Module : FakeModule
    {
        public CKR DestroyResult { get; init; } = CKR.CKR_OK;
        public int DestroyCalls { get; private set; }

        protected override bool ReleasedByFinalize => true;

        public SessionScope OpenSession()
        {
            Pkcs11Library library = Load();
            LowLevelPkcs11Library lowLevel = library.LowLevelLibrary!;
            var core = new Pkcs11SessionCore(lowLevel, slotId: default, sessionId: 1, policy: CryptoPolicy.AllowInsecure);
            return new SessionScope(new Pkcs11Session(library, new Pkcs11Slot(lowLevel, slotId: 1), core), library);
        }

        protected override CKR C_CloseSession(NativeCULong session) => CKR.CKR_OK;

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            info.CryptokiVersion = new CK_VERSION { Major = 3, Minor = 0 };
            NativeTestStructs.FillPadded(info.ManufacturerId, "Acme");
            NativeTestStructs.FillPadded(info.LibraryDescription, "Withholding PBKDF2 module");
            return CKR.CKR_OK;
        }

        protected override CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
        {
            NativeTestStructs.FillPadded(info.SlotDescription, "Withholding PBKDF2 slot");
            NativeTestStructs.FillPadded(info.ManufacturerId, "Acme");
            return CKR.CKR_OK;
        }

        protected override CKR C_GenerateKey(NativeCULong session, CK_MECHANISM mechanism, CK_ATTRIBUTE[] template, ref NativeCULong key)
        {
            if ((CKM)(ulong)mechanism.Mechanism != CKM.CKM_PKCS5_PBKD2)
                return CKR.CKR_MECHANISM_INVALID;
            key = (NativeCULong)1UL;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetAttributeValue(NativeCULong session, NativeCULong objectHandle, Span<CK_ATTRIBUTE> template)
        {
            CKR rv = CKR.CKR_OK;
            for (int i = 0; i < template.Length; i++)
            {
                ref CK_ATTRIBUTE attribute = ref template[i];
                switch ((CKA)(ulong)attribute.type)
                {
                    case CKA.CKA_CLASS:
                        AnswerAttribute(ref attribute, Ulong((ulong)CKO.CKO_SECRET_KEY));
                        break;
                    case CKA.CKA_KEY_TYPE:
                        AnswerAttribute(ref attribute, Ulong((ulong)CKK.CKK_GENERIC_SECRET));
                        break;
                    case CKA.CKA_VALUE:
                        attribute.valueLen = NativeCULong.MaxValue;
                        rv = CKR.CKR_ATTRIBUTE_SENSITIVE;
                        break;
                    default:
                        attribute.valueLen = NativeCULong.MaxValue;
                        if (rv == CKR.CKR_OK)
                            rv = CKR.CKR_ATTRIBUTE_TYPE_INVALID;
                        break;
                }
            }
            return rv;
        }

        protected override CKR C_DestroyObject(NativeCULong session, NativeCULong objectId)
        {
            DestroyCalls++;
            return DestroyResult;
        }

        private static byte[] Ulong(ulong value) => BitConverter.GetBytes(value).AsSpan(0, UnmanagedMemory.NativeULongSize).ToArray();
    }
}
