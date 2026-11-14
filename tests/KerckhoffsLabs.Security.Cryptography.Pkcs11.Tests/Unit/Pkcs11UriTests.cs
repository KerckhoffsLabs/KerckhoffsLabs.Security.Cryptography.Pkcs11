using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Uri"/> (RFC 7512): parsing, the canonical text and value equality, the field-length checks, and
/// opening a key or certificate by URI on a session's token (<see cref="Pkcs11Session.OpenKey(Pkcs11Uri)"/>,
/// <see cref="Pkcs11Session.OpenCertificate(Pkcs11Uri)"/>).
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11UriTests
{
    // ---- Parsing and text ------------------------------------------------------------------------------------------

    [Fact]
    public void Parse_ReadsEveryAttribute()
    {
        Pkcs11Uri uri = Pkcs11Uri.Parse(
            "pkcs11:library-manufacturer=SoftHSM;library-description=Implementation%20of%20PKCS11;library-version=2.6;" +
            "slot-manufacturer=Reader%20Co;slot-description=Reader%200;slot-id=7;manufacturer=Acme;model=Model%20A;" +
            "serial=0001;token=signing-prod;object=release-key;type=private;id=%01%a0");

        Assert.Equal("SoftHSM", uri.LibraryManufacturer);
        Assert.Equal("Implementation of PKCS11", uri.LibraryDescription);
        Assert.Equal(new Version(2, 6), uri.LibraryVersion);
        Assert.Equal("Reader Co", uri.SlotManufacturer);
        Assert.Equal("Reader 0", uri.SlotDescription);
        Assert.Equal(7UL, uri.SlotId);
        Assert.Equal("Acme", uri.Manufacturer);
        Assert.Equal("Model A", uri.Model);
        Assert.Equal("0001", uri.Serial);
        Assert.Equal("signing-prod", uri.Token);
        Assert.Equal("release-key", uri.Object);
        Assert.Equal(CKO.CKO_PRIVATE_KEY, uri.Type);
        Assert.Equal(new byte[] { 0x01, 0xA0 }, uri.Id!.Value.ToArray());
        Assert.True(uri.NamesLibrary);
        Assert.True(uri.NamesObject);
    }

    [Theory]
    [InlineData("public", CKO.CKO_PUBLIC_KEY)]
    [InlineData("private", CKO.CKO_PRIVATE_KEY)]
    [InlineData("cert", CKO.CKO_CERTIFICATE)]
    [InlineData("secret-key", CKO.CKO_SECRET_KEY)]
    [InlineData("data", CKO.CKO_DATA)]
    public void Type_NamesTheClass(string name, CKO objectClass)
    {
        Pkcs11Uri uri = Pkcs11Uri.Parse($"pkcs11:object=k;type={name}");
        Assert.Equal(objectClass, uri.Type);
        Assert.Equal($"pkcs11:object=k;type={name}", uri.ToString());
    }

    [Fact]
    public void Empty_NamesEverything()
    {
        Pkcs11Uri uri = Pkcs11Uri.Parse("pkcs11:");
        Assert.False(uri.NamesLibrary);
        Assert.False(uri.NamesObject);
        Assert.Equal("pkcs11:", uri.ToString());
    }

    [Fact]
    public void ToString_IsCanonical_AndRoundTrips()
    {
        Pkcs11Uri uri = Pkcs11Uri.Parse("PKCS11:token=sign%2dprod;id=%01;library-version=2;object=k%20%C3%A9;manufacturer=A&B");

        string text = uri.ToString();

        Assert.Equal("pkcs11:library-version=2.0;manufacturer=A%26B;token=sign-prod;object=k%20%C3%A9;id=%01", text);
        Assert.Equal(uri, Pkcs11Uri.Parse(text));
        Assert.Equal(uri.GetHashCode(), Pkcs11Uri.Parse(text).GetHashCode());
    }

    [Fact]
    public void Equality_IsByValue_IdIncluded()
    {
        Assert.Equal(Pkcs11Uri.Parse("pkcs11:id=%01%02"), Pkcs11Uri.Parse("pkcs11:id=%01%02"));
        Assert.NotEqual(Pkcs11Uri.Parse("pkcs11:id=%01%02"), Pkcs11Uri.Parse("pkcs11:id=%01%03"));
        Assert.NotEqual(Pkcs11Uri.Parse("pkcs11:token=a"), Pkcs11Uri.Parse("pkcs11:token=A"));
    }

    [Fact]
    public void Built_InCode_WithAnObjectAddedToATokenUri()
    {
        var token = new Pkcs11Uri { Manufacturer = "Acme", Serial = "0001", Token = "signing-prod" };

        Pkcs11Uri key = token with { Object = "release-key", Type = CKO.CKO_PRIVATE_KEY, Id = new byte[] { 0xAB } };

        Assert.Equal("pkcs11:manufacturer=Acme;serial=0001;token=signing-prod;object=release-key;type=private;id=%AB",
            key.ToString());
        Assert.False(token.NamesObject);
    }

    [Fact]
    public void Id_IsCopied_NotShared()
    {
        byte[] id = [1, 2, 3];
        var uri = new Pkcs11Uri { Id = id };
        id[0] = 9;
        Assert.Equal(new byte[] { 1, 2, 3 }, uri.Id!.Value.ToArray());
    }

    [Fact]
    public void Init_LongerThanTheField_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Token = new string('a', 33) });
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Serial = new string('1', 17) });
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Model = new string('m', 17) });
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { SlotDescription = new string('d', 65) });
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Type = CKO.CKO_HW_FEATURE });
        _ = new Pkcs11Uri { Token = new string('a', 32), SlotDescription = new string('d', 64) };
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("pkcs11")]
    [InlineData("pkcs11:token=a;token=b")]
    [InlineData("pkcs11:token=a b")]
    [InlineData("pkcs11:token=a?pin-value=1234")]
    [InlineData("pkcs11:x-vendor=1")]
    public void TryParse_Refuses_WithoutThrowing(string? text)
    {
        Assert.False(Pkcs11Uri.TryParse(text, out Pkcs11Uri? uri));
        Assert.Null(uri);
    }

    [Fact]
    public void TryParse_Accepts()
    {
        Assert.True(Pkcs11Uri.TryParse("pkcs11:token=a", out Pkcs11Uri? uri));
        Assert.Equal("a", uri.Token);
    }

    [Fact]
    public void Parse_Null_Throws() => Assert.Throws<ArgumentNullException>(() => Pkcs11Uri.Parse(null!));

    // ---- Opening a key or certificate by URI ---------------------------------------------------------------------

    private static (LoginTokenModule Module, Pkcs11Library Library) TokenWithObjects()
    {
        var module = new LoginTokenModule();
        var keyId = new Dictionary<CKA, byte[]> { [CKA.CKA_ID] = [0x01, 0x02] };
        module.AddObject(CKO.CKO_PRIVATE_KEY, "release-key", isPrivate: false, keyType: CKK.CKK_RSA, more: keyId);
        module.AddObject(CKO.CKO_PUBLIC_KEY, "release-key", isPrivate: false, keyType: CKK.CKK_RSA, more: keyId);
        module.AddObject(CKO.CKO_SECRET_KEY, "wrap-key", isPrivate: false, keyType: CKK.CKK_AES);
        module.AddObject(CKO.CKO_CERTIFICATE, "release-key", isPrivate: false, value: SelfSigned(), more: new Dictionary<CKA, byte[]>
        {
            [CKA.CKA_CERTIFICATE_TYPE] = LoginTokenModule.Ulong((ulong)CKC.CKC_X_509),
            [CKA.CKA_ID] = [0x01, 0x02],
        });
        return (module, module.Load());
    }

    [Theory]
    [InlineData("pkcs11:object=release-key;type=private")]
    [InlineData("pkcs11:token=login-token;id=%01%02;type=private")]
    [InlineData("pkcs11:object=release-key;id=%01%02")]
    public void OpenKey_ByUri_OpensTheKey(string text)
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession())
        using (Pkcs11Key key = session.OpenKey(Pkcs11Uri.Parse(text)))
        {
            Assert.Equal(CKK.CKK_RSA, key.KeyType);
            Assert.Equal("release-key", key.Label);
        }
    }

    [Fact]
    public void OpenKey_SecretKeyByType()
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession())
        using (Pkcs11Key key = session.OpenKey(Pkcs11Uri.Parse("pkcs11:object=wrap-key;type=secret-key")))
            Assert.Equal(CKK.CKK_AES, key.KeyType);
    }

    [Fact]
    public void OpenCertificate_ByUri_OpensTheCertificate()
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession())
        using (Pkcs11Certificate certificate = session.OpenCertificate(Pkcs11Uri.Parse("pkcs11:object=release-key;type=cert")))
            Assert.Contains("CN=uri-test", certificate.Certificate.Subject, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("pkcs11:token=login-token", "names no object")]
    [InlineData("pkcs11:object=release-key;type=cert", "not a key")]
    [InlineData("pkcs11:object=release-key;type=data", "not a key")]
    [InlineData("pkcs11:id=", "is empty")]
    [InlineData("pkcs11:token=another-token;object=release-key", "another token")]
    [InlineData("pkcs11:serial=nope;object=release-key", "another token")]
    [InlineData("pkcs11:slot-id=5;object=release-key", "another token")]
    public void OpenKey_ByUri_Refuses(string text, string why)
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession())
        {
            var ex = Assert.Throws<ArgumentException>(() => session.OpenKey(Pkcs11Uri.Parse(text)));
            Assert.Contains(why, ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void OpenCertificate_ByUri_KeyType_IsRefused()
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession())
        {
            var ex = Assert.Throws<ArgumentException>(
                () => session.OpenCertificate(Pkcs11Uri.Parse("pkcs11:object=release-key;type=private")));
            Assert.Contains("not a certificate", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void OpenKey_ByUri_NoMatch_IsNotFound()
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession())
            Assert.Throws<Pkcs11ObjectNotFoundException>(() => session.OpenKey(Pkcs11Uri.Parse("pkcs11:object=missing")));
    }

    private static byte[] SelfSigned()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=uri-test", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return certificate.RawData;
    }
}
