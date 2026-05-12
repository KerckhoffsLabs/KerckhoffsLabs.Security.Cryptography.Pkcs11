using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Fixtures;
using Microsoft.DotNet.XUnitExtensions;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.HighLevel.Keys;

internal static class WrapUnwrapKeyTestCases
{
    internal static void Assert_AesKeyWrapPad_RoundTrip(IPkcs11Backend backend)
    {
        var session = TestKeys.OpenLoggedInSession(backend);
        try
        {
            ObjectHandle kek = session.GenerateAesKey(bitLength: 256);
            ObjectHandle dataKey = session.GenerateAesKey(bitLength: 256);
            try
            {
                using var wrapMech = new Mechanism(CKM.CKM_AES_KEY_WRAP_PAD);
                byte[] wrapped = session.WrapKey(wrapMech, kek, dataKey);
                Assert.NotEmpty(wrapped);

                using var attrClass     = new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                using var attrKeyType   = new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_AES);
                using var attrToken     = new ObjectAttribute(CKA.CKA_TOKEN, false);
                using var attrSensitive = new ObjectAttribute(CKA.CKA_SENSITIVE, true);
                using var attrExtract   = new ObjectAttribute(CKA.CKA_EXTRACTABLE, false);
                using var attrEncrypt   = new ObjectAttribute(CKA.CKA_ENCRYPT, true);
                using var attrDecrypt   = new ObjectAttribute(CKA.CKA_DECRYPT, true);
                var template = new List<ObjectAttribute> { attrClass, attrKeyType, attrToken, attrSensitive, attrExtract, attrEncrypt, attrDecrypt };

                ObjectHandle unwrapped = session.UnwrapKey(wrapMech, kek, wrapped, template);
                try
                {
                    Assert.NotEqual(0UL, unwrapped.ObjectId);
                }
                finally
                {
                    session.DestroyObject(unwrapped);
                }
            }
            finally
            {
                session.DestroyObject(dataKey);
                session.DestroyObject(kek);
            }
        }
        finally
        {
            session.Logout();
            session.CloseSession();
        }
    }
}

[Collection("SoftHsm")]
public sealed class WrapUnwrapKeyTests_SoftHsm(SoftHsmBackendFixture f)
{
    private readonly SoftHsmBackendFixture _backend = f;
    public static bool SoftHsmAvailable => SoftHsmBackendFixture.SoftHsmAvailable;

    [ConditionalFact(nameof(SoftHsmAvailable))]
    public void AesKeyWrapPad_RoundTrip() => WrapUnwrapKeyTestCases.Assert_AesKeyWrapPad_RoundTrip(_backend);
}
