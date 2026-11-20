using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
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
        Assert.Equal(new SlotId(7), uri.SlotId);
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

    // A slot-id is in the TokenInfo, so Matches(TokenInfo) takes it.
    [Fact]
    public void MatchesTokenInfo_SlotId_IsCompared()
    {
        var info = new TokenInfo((NativeCULong)3UL, TokenInfoOf("tok", "0001"));

        Assert.True(Pkcs11Uri.Parse("pkcs11:token=tok;slot-id=3").Matches(info));
        Assert.False(Pkcs11Uri.Parse("pkcs11:token=tok;slot-id=4").Matches(info));
        Assert.False(Pkcs11Uri.Parse("pkcs11:token=tok;slot-description=r").Matches(info));
    }

    // A field the module filled with bytes that are not UTF-8, or a serial number that is not printable ASCII, is
    // refused rather than left out: a URI without it would name every token sharing the other fields. It is what the
    // token reported, not a misuse of the API, so a Pkcs11TokenException.
    [Theory]
    [InlineData(true, "label")]
    [InlineData(false, "serial number")]
    public void ForToken_UnnamableField_IsRefused(bool label, string field)
    {
        CK_TOKEN_INFO native = TokenInfoOf("tok", "0001");
        if (label)
            native.Label[0] = 0xFF;
        else
            native.SerialNumber[0] = 0x01;
        var info = new TokenInfo((NativeCULong)0UL, native);

        var ex = Assert.Throws<Pkcs11TokenException>(() => Pkcs11Uri.ForToken(info));

        Assert.Equal(CKR.CKR_TOKEN_NOT_RECOGNIZED, ex.ReturnValue);
        Assert.Contains(field, ex.Message, StringComparison.Ordinal);
        Assert.Contains("GetSlot", ex.Message, StringComparison.Ordinal);
    }

    // A field whose bytes are not UTF-8 matches no URI value, not even U+FFFD, which its decoded text holds: compared as
    // bytes, two tokens that differ only there are told apart.
    [Fact]
    public void Matches_FieldNotUtf8_MatchesNoValue_NotEvenTheReplacementCharacter()
    {
        CK_TOKEN_INFO native = TokenInfoOf("tok", "0001");
        native.Label[0] = 0xFF;
        var info = new TokenInfo((NativeCULong)0UL, native);
        Assert.Equal("\uFFFDok", info.Label);

        Assert.False(new Pkcs11Uri { Token = "\uFFFDok" }.Matches(info));
        Assert.True(new Pkcs11Uri { Serial = "0001" }.Matches(info));
    }

    // A field that genuinely holds U+FFFD (its UTF-8, EF BF BD) is UTF-8: it is named, and matched.
    [Fact]
    public void ForToken_FieldHoldingTheReplacementCharacter_IsNamed()
    {
        var info = new TokenInfo((NativeCULong)0UL, TokenInfoOf("\uFFFDok", "0001"));

        Pkcs11Uri uri = Pkcs11Uri.ForToken(info);

        Assert.Equal("\uFFFDok", uri.Token);
        Assert.True(uri.Matches(info));
    }

    // An empty field is carried as an empty value, which matches only an empty field (RFC 7512), not left out.
    [Fact]
    public void ForToken_EmptyField_IsAnEmptyValue()
    {
        var info = new TokenInfo((NativeCULong)0UL, TokenInfoOf("", "0001"));

        Pkcs11Uri uri = Pkcs11Uri.ForToken(info);

        Assert.Equal("", uri.Token);
        Assert.Equal("pkcs11:manufacturer=Acme;model=M1;serial=0001;token=", uri.ToString());
        Assert.True(uri.Matches(info));
        Assert.False(uri.Matches(new TokenInfo((NativeCULong)0UL, TokenInfoOf("tok", "0001"))));
        Assert.Equal(uri, Pkcs11Uri.Parse(uri.ToString()));
    }

    // Trailing blanks and NULs are padding in the PKCS#11 field, so they are not significant in the wanted value either.
    [Theory]
    [InlineData("pkcs11:token=tok%20")]
    [InlineData("pkcs11:token=tok%00%20")]
    [InlineData("pkcs11:token=tok;serial=0001%20%20")]
    public void Matches_TrailingPaddingInTheValue_IsNotSignificant(string text)
    {
        var info = new TokenInfo((NativeCULong)0UL, TokenInfoOf("tok", "0001"));

        Assert.True(Pkcs11Uri.Parse(text).Matches(info));
        Assert.True(new Pkcs11Uri { Token = "tok \0" }.Matches(info));
        Assert.False(Pkcs11Uri.Parse("pkcs11:token=%20tok").Matches(info));
    }

    // NUL padding (a module that pads with NUL rather than blanks) is removed like blank padding.
    [Fact]
    public void ForToken_NulPadding_Removed()
    {
        CK_TOKEN_INFO native = TokenInfoOf("tok", "0001");
        native.Label[3] = 0;
        native.Label[4] = 0;
        var info = new TokenInfo((NativeCULong)0UL, native);

        Assert.Equal("tok", info.Label);
        Assert.Equal("tok", Pkcs11Uri.ForToken(info).Token);
    }

    // A serial number padded with NULs is named without them, not refused as unprintable.
    [Fact]
    public void ForToken_SerialWithNulPadding_IsNamed()
    {
        CK_TOKEN_INFO native = TokenInfoOf("tok", "0001");
        native.SerialNumber[4] = 0;
        native.SerialNumber[5] = 0;
        var info = new TokenInfo((NativeCULong)0UL, native);

        Assert.Equal("0001", Pkcs11Uri.ForToken(info).Serial);
    }

    // The padding of a token, slot or library value is removed before the length check: a 32-byte label followed by
    // a blank fits the 32-byte field, parsed or set in code.
    [Fact]
    public void PaddedValue_IsUnpaddedBeforeTheLengthCheck()
    {
        string label = new('a', 32);

        Assert.Equal(label, Pkcs11Uri.Parse("pkcs11:token=" + label + "%20").Token);
        Assert.Equal(label, Pkcs11Uri.Parse("pkcs11:token=" + label + "%00%20%00").Token);
        Assert.Equal(label, new Pkcs11Uri { Token = label + " \0" }.Token);
        Assert.Equal(new string('d', 64), new Pkcs11Uri { SlotDescription = new string('d', 64) + "  " }.SlotDescription);
        Assert.Throws<FormatException>(() => Pkcs11Uri.Parse("pkcs11:token=" + label + "a%20"));
    }

    // And before the printable-ASCII check of a serial number: a NUL that pads it is not part of it.
    [Fact]
    public void PaddedSerial_IsUnpaddedBeforeThePrintableCheck()
    {
        Assert.Equal("abc", Pkcs11Uri.Parse("pkcs11:serial=abc%00").Serial);
        Assert.Equal("abc", Pkcs11Uri.Parse("pkcs11:serial=abc%20%00").Serial);
        Assert.Equal("abc", new Pkcs11Uri { Serial = "abc\0 " }.Serial);
        Assert.Throws<FormatException>(() => Pkcs11Uri.Parse("pkcs11:serial=a%00bc"));
    }

    // The padding is not part of the value, so not of the canonical text, the equality or the hash.
    [Theory]
    [InlineData("pkcs11:token=abc", "pkcs11:token=abc%20")]
    [InlineData("pkcs11:token=abc", "pkcs11:token=abc%00")]
    [InlineData("pkcs11:slot-description=r;library-manufacturer=m", "pkcs11:slot-description=r%20;library-manufacturer=m%20%20")]
    public void PaddedValue_IsTheSameUri(string plain, string padded)
    {
        Pkcs11Uri a = Pkcs11Uri.Parse(plain);
        Pkcs11Uri b = Pkcs11Uri.Parse(padded);

        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(a.ToString(), b.ToString());
    }

    [Fact]
    public void PaddedValue_SetInCode_IsTheSameUri()
    {
        var padded = new Pkcs11Uri { Token = "abc \0", Model = "M1 " };

        Assert.Equal(Pkcs11Uri.Parse("pkcs11:token=abc;model=M1"), padded);
        Assert.Equal("pkcs11:model=M1;token=abc", padded.ToString());
    }

    // CKA_LABEL is variable-length, not padded: an object's label is kept exactly, a trailing blank included.
    [Fact]
    public void Object_IsKeptExactly()
    {
        Pkcs11Uri padded = Pkcs11Uri.Parse("pkcs11:object=key%20");

        Assert.Equal("key ", padded.Object);
        Assert.Equal("key\0", new Pkcs11Uri { Object = "key\0" }.Object);
        Assert.NotEqual(Pkcs11Uri.Parse("pkcs11:object=key"), padded);
        Assert.Equal("pkcs11:object=key%20", padded.ToString());
    }

    // An unknown path attribute's name may be a mistyped secret (a PIN where a name should be): the message gives its
    // position among the path attributes, never its name.
    [Theory]
    [InlineData("pkcs11:mysecretpin1234=x", "mysecretpin1234", 1)]
    [InlineData("pkcs11:token=a;serial=1;mysecretpin1234=x", "mysecretpin1234", 3)]
    [InlineData("pkcs11:token=a;x-vendor=1", "x-vendor", 2)]
    public void Parse_UnknownPathAttribute_GivesItsPosition_NotItsName(string text, string name, int position)
    {
        var ex = Assert.Throws<FormatException>(() => Pkcs11Uri.Parse(text));

        Assert.DoesNotContain(name, ex.Message, StringComparison.Ordinal);
        Assert.Contains("unknown path attribute", ex.Message, StringComparison.Ordinal);
        Assert.Contains($"position {position} ", ex.Message, StringComparison.Ordinal);
    }

    // A known attribute may still be named: the name is the library's, not the URI's.
    [Fact]
    public void Parse_RepeatedKnownAttribute_IsNamed()
    {
        var ex = Assert.Throws<FormatException>(() => Pkcs11Uri.Parse("pkcs11:token=a;Token=b"));

        Assert.Contains("'token'", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("pkcs11:token=a?pin%2Dvalue=1234")]
    [InlineData("pkcs11:token=a?PIN-VALUE=1234")]
    [InlineData("pkcs11:token=a?Module-Path=/x.so")]
    [InlineData("pkcs11:token=a?x=1;pin-value=1234")]   // ';' is not a query character
    [InlineData("pkcs11:token=a?pin-value =1234")]      // nor is a space, in a name or a value
    [InlineData("pkcs11:token=a?x#pin-value=1234")]     // '#' starts a fragment
    [InlineData("pkcs11:token=a?x=1&pin-value")]        // an attribute without a value
    [InlineData("pkcs11:token=a?x=1&&pin-value=1234")]
    [InlineData("pkcs11:token=a?x=%2")]
    public void Parse_RefusedQueryAttribute_SpelledOtherwise_StillRefused(string text)
    {
        var ex = Assert.Throws<FormatException>(() => Pkcs11Uri.Parse(text));

        Assert.DoesNotContain("1234", ex.Message, StringComparison.Ordinal);
    }

    private static CK_TOKEN_INFO TokenInfoOf(string label, string serial)
    {
        var info = new CK_TOKEN_INFO();
        NativeTestStructs.FillPadded(info.Label, label);
        NativeTestStructs.FillPadded(info.ManufacturerId, "Acme");
        NativeTestStructs.FillPadded(info.Model, "M1");
        NativeTestStructs.FillPadded(info.SerialNumber, serial);
        NativeTestStructs.FillPadded(info.UtcTime, "");
        return info;
    }

    // Matches(TokenInfo) cannot satisfy slot or module attributes: a URI that has some matches no token on its own.
    [Fact]
    public void MatchesTokenInfo_WithSlotOrLibraryAttributes_MatchesNothing()
    {
        Assert.False(Pkcs11Uri.Parse("pkcs11:slot-description=Reader%200").NamesToken);
        Assert.True(Pkcs11Uri.Parse("pkcs11:slot-description=Reader%200").NamesSlot);
        Assert.True(Pkcs11Uri.Parse("pkcs11:token=a").NamesToken);
        Assert.True(Pkcs11Uri.Parse("pkcs11:slot-id=3").NamesSlot);
    }

    // Each public Matches overload checks one part, and matches only a URI that names nothing outside it: ignoring an
    // attribute it cannot check would select more than the URI names.
    [Fact]
    public void MatchesSlotInfo_WithTokenOrLibraryAttributes_MatchesNothing()
    {
        SlotInfo slot = SlotInfoOf(3, "Reader 0", "Acme");

        Assert.True(Pkcs11Uri.Parse("pkcs11:slot-description=Reader%200;slot-manufacturer=Acme;slot-id=3").Matches(slot));
        Assert.True(Pkcs11Uri.Parse("pkcs11:").Matches(slot));
        Assert.False(Pkcs11Uri.Parse("pkcs11:slot-id=4").Matches(slot));
        Assert.False(Pkcs11Uri.Parse("pkcs11:slot-description=Reader%200;token=tok").Matches(slot));
        Assert.False(Pkcs11Uri.Parse("pkcs11:slot-description=Reader%200;library-manufacturer=Acme").Matches(slot));
    }

    [Fact]
    public void MatchesLibraryInfo_WithSlotOrTokenAttributes_MatchesNothing()
    {
        LibraryInfo library = LibraryInfoOf("Acme", "Acme PKCS#11", 2, 40);

        Assert.True(Pkcs11Uri.Parse("pkcs11:library-manufacturer=Acme;library-description=Acme%20PKCS%2311;library-version=2.40")
            .Matches(library));
        Assert.True(Pkcs11Uri.Parse("pkcs11:").Matches(library));
        Assert.False(Pkcs11Uri.Parse("pkcs11:library-version=2.41").Matches(library));
        Assert.False(Pkcs11Uri.Parse("pkcs11:library-manufacturer=Acme;token=tok").Matches(library));
        Assert.False(Pkcs11Uri.Parse("pkcs11:library-manufacturer=Acme;slot-id=3").Matches(library));
        Assert.False(Pkcs11Uri.Parse("pkcs11:library-manufacturer=Acme;slot-description=r").Matches(library));
    }

    [Fact]
    public void MatchesTokenInfo_WithLibraryAttributes_MatchesNothing()
    {
        var info = new TokenInfo((NativeCULong)3UL, TokenInfoOf("tok", "0001"));

        Assert.True(Pkcs11Uri.Parse("pkcs11:token=tok").Matches(info));
        Assert.False(Pkcs11Uri.Parse("pkcs11:token=tok;library-manufacturer=Acme").Matches(info));
    }

    // The object attributes select an object on the token, not the token: no overload considers them.
    [Fact]
    public void Matches_ObjectAttributes_AreNotConsidered()
    {
        Pkcs11Uri uri = Pkcs11Uri.Parse("pkcs11:object=key;type=private;id=%01");

        Assert.True(uri.Matches(new TokenInfo((NativeCULong)3UL, TokenInfoOf("tok", "0001"))));
        Assert.True(uri.Matches(SlotInfoOf(3, "Reader 0", "Acme")));
        Assert.True(uri.Matches(LibraryInfoOf("Acme", "Acme PKCS#11", 2, 40)));
    }

    private static SlotInfo SlotInfoOf(ulong slotId, string description, string manufacturer)
    {
        var native = new CK_SLOT_INFO();
        NativeTestStructs.FillPadded(native.SlotDescription, description);
        NativeTestStructs.FillPadded(native.ManufacturerId, manufacturer);
        return new SlotInfo((NativeCULong)slotId, native);
    }

    private static LibraryInfo LibraryInfoOf(string manufacturer, string description, byte major, byte minor)
    {
        var native = new CK_INFO
        {
            CryptokiVersion = new CK_VERSION { Major = 3, Minor = 2 },
            LibraryVersion = new CK_VERSION { Major = major, Minor = minor },
        };
        NativeTestStructs.FillPadded(native.ManufacturerId, manufacturer);
        NativeTestStructs.FillPadded(native.LibraryDescription, description);
        return new LibraryInfo(native);
    }

    // Values set in code are checked as Parse checks them: a version that is not a CK_VERSION, a serial number that
    // is not printable ASCII.
    [Fact]
    public void Init_InvalidVersionOrSerial_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { LibraryVersion = new Version(1, 300) });
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { LibraryVersion = new Version(1, 2, 3) });
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Serial = "caf\u00e9" });
        var ex = Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Token = new string('a', 33) });
        Assert.Equal(nameof(Pkcs11Uri.Token), ex.ParamName);
        _ = new Pkcs11Uri { LibraryVersion = new Version(2, 40), Serial = "0123-ABCD" };
    }

    [Theory]
    [InlineData("pkcs11:serial=caf%C3%A9", "printable ASCII")]
    [InlineData("pkcs11:token=a;bad%0Aname=x", "unknown path attribute")]
    public void Parse_InvalidSerialOrName_IsRefused_WithoutEchoingThem(string text, string why)
    {
        var ex = Assert.Throws<FormatException>(() => Pkcs11Uri.Parse(text));
        Assert.Contains(why, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("\n", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("pkcs11:token=a?")]
    [InlineData("pkcs11:token=a?x-vendor=1&other=")]
    [InlineData("pkcs11:token=a?x_v=:[]@!$'()*+,=/?|%2A-._~")]   // every pk11-qchar
    public void Parse_EmptyOrUnknownQuery_IsIgnored(string text)
        => Assert.Equal("pkcs11:token=a", Pkcs11Uri.Parse(text).ToString());

    // Attribute names are case-insensitive (RFC 5234 quoted strings), written in lower case; the folding is ASCII only,
    // so a look-alike (a Kelvin sign for 'k') names nothing. A type value is a value, compared as written (RFC 7512
    // section 2.6): "Secret-KEY" names no type.
    [Fact]
    public void Parse_NamesAreCaseInsensitive_TypeValueIsNot()
    {
        Pkcs11Uri uri = Pkcs11Uri.Parse("pkcs11:TOKEN=a;Slot-ID=3;Object=k;Type=secret-key");

        Assert.Equal("pkcs11:slot-id=3;token=a;object=k;type=secret-key", uri.ToString());
        Assert.Throws<FormatException>(() => Pkcs11Uri.Parse("pkcs11:object=k;type=Secret-KEY"));
        Assert.Throws<FormatException>(() => Pkcs11Uri.Parse("pkcs11:token=a;Token=b"));
        Assert.Throws<FormatException>(() => Pkcs11Uri.Parse("pkcs11:object=k;type=secret-%E2%84%AAey"));
        Assert.Throws<FormatException>(() => Pkcs11Uri.Parse("pkcs11:to%E2%84%AAen=a"));
    }

    // An unpaired surrogate would encode to U+FFFD: two different values would share a text and compare equal.
    // Not InlineData: an attribute argument is stored as UTF-8, where the surrogate would already be U+FFFD.
    [Fact]
    public void Init_InvalidUtf16_IsRefused()
    {
        foreach (string value in new[] { "\uD800", "\uDC00", "a\uDBFFb" })
            RefusedEverywhere(value);
        Assert.Equal("\U0001F600", new Pkcs11Uri { Object = "\U0001F600" }.Object);
        Assert.NotEqual(new Pkcs11Uri { Object = "\uFFFD" }, new Pkcs11Uri { Object = "\uFFFE" });
    }

    private static void RefusedEverywhere(string value)
    {
        Assert.Equal(nameof(Pkcs11Uri.Object),
            Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Object = value }).ParamName);
        Assert.Equal(nameof(Pkcs11Uri.Token),
            Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Token = value }).ParamName);
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { SlotDescription = value });
        Assert.Throws<ArgumentException>(() => new Pkcs11Uri { LibraryManufacturer = value });
    }

    [Fact]
    public void Init_UnnamedType_ReportsTheProperty()
        => Assert.Equal(nameof(Pkcs11Uri.Type),
            Assert.Throws<ArgumentException>(() => new Pkcs11Uri { Type = CKO.CKO_HW_FEATURE }).ParamName);

    [Fact]
    public void Id_ReturnsACopy()
    {
        Pkcs11Uri uri = Pkcs11Uri.Parse("pkcs11:id=%01%02");
        Assert.True(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(uri.Id!.Value, out ArraySegment<byte> segment));
        segment.Array![0] = 9;
        Assert.Equal("pkcs11:id=%01%02", uri.ToString());
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
    [InlineData("pkcs11:token=a?module-path=/x.so")]
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
        module.AddObject(CKO.CKO_DATA, "config", isPrivate: false, value: "settings"u8.ToArray());
        return (module, module.Load());
    }

    // The Try forms match as the throwing ones do: false only when nothing matches, the same refusals otherwise.
    [Fact]
    public void TryOpenKeyAndCertificate_ByUri()
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
        {
            Assert.True(session.TryOpenKey(Pkcs11Uri.Parse("pkcs11:object=release-key;type=private"), out Pkcs11Key? key));
            using (key)
                Assert.Equal(CKK.CKK_RSA, key.KeyType);
            Assert.False(session.TryOpenKey(Pkcs11Uri.Parse("pkcs11:object=missing"), out _));
            Assert.Throws<ArgumentException>(() => session.TryOpenKey(Pkcs11Uri.Parse("pkcs11:object=release-key;type=cert"), out _));

            Assert.True(session.TryOpenCertificate(Pkcs11Uri.Parse("pkcs11:object=release-key;type=cert"), out Pkcs11Certificate? certificate));
            using (certificate)
                Assert.Contains("CN=uri-test", certificate.Certificate.Subject, StringComparison.Ordinal);
            Assert.False(session.TryOpenCertificate(Pkcs11Uri.Parse("pkcs11:object=missing"), out _));
            Assert.Throws<ArgumentException>(
                () => session.TryOpenCertificate(Pkcs11Uri.Parse("pkcs11:token=another-token;object=release-key"), out _));
        }
    }

    // A data object by URI: type=data, or no type (the only other class a URI names); a key or certificate type is
    // refused, as OpenKey refuses a certificate's.
    [Theory]
    [InlineData("pkcs11:object=config;type=data")]
    [InlineData("pkcs11:object=config")]
    public void OpenObject_ByUri_OpensTheDataObject(string text)
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
        {
            using (Pkcs11Object data = session.OpenObject(Pkcs11Uri.Parse(text)))
            {
                Assert.Equal(CKO.CKO_DATA, data.ObjectClass);
                Assert.Equal("config", data.Label);
            }
            Assert.True(session.TryOpenObject(Pkcs11Uri.Parse(text), out Pkcs11Object? again));
            again!.Dispose();
            Assert.False(session.TryOpenObject(Pkcs11Uri.Parse("pkcs11:object=missing;type=data"), out _));
            Assert.Throws<Pkcs11ObjectNotFoundException>(() => session.OpenObject(Pkcs11Uri.Parse("pkcs11:object=release-key")));
            var ex = Assert.Throws<ArgumentException>(() => session.OpenObject(Pkcs11Uri.Parse("pkcs11:object=release-key;type=cert")));
            Assert.Contains("not a data object", ex.Message, StringComparison.Ordinal);
        }
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
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
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
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
        using (Pkcs11Key key = session.OpenKey(Pkcs11Uri.Parse("pkcs11:object=wrap-key;type=secret-key")))
            Assert.Equal(CKK.CKK_AES, key.KeyType);
    }

    [Fact]
    public void OpenCertificate_ByUri_OpensTheCertificate()
    {
        (LoginTokenModule module, Pkcs11Library library) = TokenWithObjects();
        using (module)
        using (library)
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
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
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
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
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
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
        using (Pkcs11Session session = Assert.Single(library.GetSlotList()).OpenSession(SessionAccess.ReadOnly))
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
