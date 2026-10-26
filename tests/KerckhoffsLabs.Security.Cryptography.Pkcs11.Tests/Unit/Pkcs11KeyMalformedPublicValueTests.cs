using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.SoftToken;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// Public-key values a token answers with but no key can have: an empty or zero integer for the RSA
/// modulus and exponent and the DSA parameters, and a key size too large for an <see cref="int"/>. Export
/// refuses them with a <see cref="Pkcs11Exception"/>, as it does an unreadable attribute, rather than
/// failing inside the encoder; KeySize reports them as unknown.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11KeyMalformedPublicValueTests
{
    private static readonly byte[] Modulus = [0xC3, .. Enumerable.Repeat((byte)0x5A, 254), 0x6B];
    private static readonly byte[] Exponent = [0x01, 0x00, 0x01];

    public static TheoryData<CKA, byte[]> MalformedRsaValues() => new()
    {
        { CKA.CKA_MODULUS, [] },
        { CKA.CKA_MODULUS, new byte[256] },
        { CKA.CKA_PUBLIC_EXPONENT, [] },
        { CKA.CKA_PUBLIC_EXPONENT, [0x00] },
    };

    [Theory]
    [MemberData(nameof(MalformedRsaValues))]
    public void Export_Rsa_EmptyOrZeroValue_ThrowsAttributeValueInvalid(CKA attribute, byte[] value)
    {
        using var fake = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            _ when ca == attribute => (CKR.CKR_OK, value),
            CKA.CKA_MODULUS => (CKR.CKR_OK, Modulus),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, Exponent),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        });
        Pkcs11Key key = fake;

        foreach (Pkcs11KeyBlobFormat format in new[] { Pkcs11KeyBlobFormat.SubjectPublicKeyInfo, Pkcs11KeyBlobFormat.RawPublicKey })
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Export(format));
            Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, ex.ReturnValue);
            Assert.Contains(attribute.ToString(), ex.Message);
        }
    }

    public static TheoryData<CKA, byte[]> MalformedDsaValues() => new()
    {
        { CKA.CKA_PRIME, [] },
        { CKA.CKA_SUBPRIME, [] },
        { CKA.CKA_BASE, [] },
        { CKA.CKA_VALUE, [] },
        { CKA.CKA_PRIME, new byte[128] },
        { CKA.CKA_VALUE, new byte[128] },
    };

    [Theory]
    [MemberData(nameof(MalformedDsaValues))]
    public void Export_Dsa_EmptyOrZeroValue_ThrowsAttributeValueInvalid(CKA attribute, byte[] value)
    {
        // Export only encodes the integers, so any non-zero ones stand in for a key: no platform DSA
        // needed, which macOS's BCL doesn't fully have.
        (CKR, byte[]?) Respond(CKA ca) => ca switch
        {
            _ when ca == attribute => (CKR.CKR_OK, value),
            CKA.CKA_PRIME => (CKR.CKR_OK, [0xC3, .. Enumerable.Repeat((byte)0x5A, 126), 0x6B]),
            CKA.CKA_SUBPRIME => (CKR.CKR_OK, [0x9D, .. Enumerable.Repeat((byte)0x33, 18), 0x01]),
            CKA.CKA_BASE => (CKR.CKR_OK, [0x02]),
            CKA.CKA_VALUE => (CKR.CKR_OK, [0x41, .. Enumerable.Repeat((byte)0x17, 126), 0x09]),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        };
        using var fake = FakeKeys.Create(CKK.CKK_DSA, Respond, respondFor: (_, ca) => Respond(ca));
        Pkcs11Key key = fake;

        // The raw format is y alone, so only y is read for it.
        Pkcs11KeyBlobFormat[] formats = [Pkcs11KeyBlobFormat.SubjectPublicKeyInfo, Pkcs11KeyBlobFormat.RawPublicKey];
        foreach (Pkcs11KeyBlobFormat format in formats.Where(f => f != Pkcs11KeyBlobFormat.RawPublicKey || attribute == CKA.CKA_VALUE))
        {
            var ex = Assert.ThrowsAny<Pkcs11Exception>(() => key.Export(format));
            Assert.Equal(CKR.CKR_ATTRIBUTE_VALUE_INVALID, ex.ReturnValue);
            Assert.Contains(attribute.ToString(), ex.Message);
        }
    }

    // A modulus with leading zero bytes is still that modulus, and exports as the BCL writes it.
    [Fact]
    public void Export_Rsa_ModulusWithLeadingZeros_IsTrimmed()
    {
        using var fake = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS => (CKR.CKR_OK, [0x00, 0x00, .. Modulus]),
            CKA.CKA_PUBLIC_EXPONENT => (CKR.CKR_OK, Exponent),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        });
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = Modulus, Exponent = Exponent });

        Assert.Equal(rsa.ExportRSAPublicKey(), ((Pkcs11Key)fake).Export(Pkcs11KeyBlobFormat.RawPublicKey));
    }

    // CKA_MODULUS_BITS of 2^31 or more, or a CKA_VALUE_LEN of 2^28 bytes or more, is a size KeySize can't
    // hold: it is unknown, as for an attribute the token won't reveal, rather than an OverflowException.
    [Theory]
    [InlineData(CKK.CKK_RSA, CKA.CKA_MODULUS_BITS, 0x8000_0000UL)]
    [InlineData(CKK.CKK_RSA, CKA.CKA_MODULUS_BITS, ulong.MaxValue - 1)]
    [InlineData(CKK.CKK_AES, CKA.CKA_VALUE_LEN, 0x1000_0000UL)]
    [InlineData(CKK.CKK_GENERIC_SECRET, CKA.CKA_VALUE_LEN, ulong.MaxValue - 1)]
    public void KeySize_TooLargeForAnInt_IsNull(CKK keyType, CKA attribute, ulong value)
    {
        using var fake = FakeKeys.Create(keyType, ca => ca == attribute
            ? (CKR.CKR_OK, UlongAttr(value))
            : (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null));

        Assert.Null(((Pkcs11Key)fake).KeySize);
    }

    // A CKA_MODULUS_BITS too large for an int gives way to the modulus itself, as an unreadable one does.
    [Fact]
    public void KeySize_RsaModulusBitsTooLarge_IsTheModulusBitLength()
    {
        using var fake = FakeKeys.Create(CKK.CKK_RSA, ca => ca switch
        {
            CKA.CKA_MODULUS_BITS => (CKR.CKR_OK, UlongAttr(0x8000_0000UL)),
            CKA.CKA_MODULUS => (CKR.CKR_OK, Modulus),
            _ => (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null),
        });

        Assert.Equal(2048, ((Pkcs11Key)fake).KeySize);
    }

    // The largest sizes that fit are still reported: SoftHSM, for one, makes generic secrets of up to 128 MB.
    [Theory]
    [InlineData(CKK.CKK_RSA, CKA.CKA_MODULUS_BITS, 0x7FFF_FFFFUL, int.MaxValue)]
    [InlineData(CKK.CKK_GENERIC_SECRET, CKA.CKA_VALUE_LEN, 0x0FFF_FFFFUL, 0x7FFF_FFF8)]
    [InlineData(CKK.CKK_AES, CKA.CKA_VALUE_LEN, 32UL, 256)]
    public void KeySize_LargestThatFits_IsReported(CKK keyType, CKA attribute, ulong value, int bits)
    {
        using var fake = FakeKeys.Create(keyType, ca => ca == attribute
            ? (CKR.CKR_OK, UlongAttr(value))
            : (CKR.CKR_ATTRIBUTE_TYPE_INVALID, null));

        Assert.Equal(bits, ((Pkcs11Key)fake).KeySize);
    }

    private static byte[] UlongAttr(ulong v) => BitConverter.GetBytes(v).AsSpan(0, UnmanagedMemory.NativeULongSize).ToArray();
}
