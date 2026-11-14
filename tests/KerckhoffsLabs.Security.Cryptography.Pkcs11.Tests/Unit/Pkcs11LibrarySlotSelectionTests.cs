using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Exceptions;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit;

/// <summary>
/// <see cref="Pkcs11Library.GetSlotByTokenSerial"/>, <see cref="Pkcs11Library.FindSlot"/> and
/// <see cref="Pkcs11Library.GetSlotByUri(string)"/>: exactly one present token, matched ordinally on fields with their padding
/// removed; none is <c>CKR_TOKEN_NOT_PRESENT</c>, more than one is refused naming the slots. The URI is RFC 7512's,
/// read strictly.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class Pkcs11LibrarySlotSelectionTests
{
    private sealed record Token(ulong SlotId, string Label, string Serial, string Manufacturer = "Acme",
        string Model = "Model A", string SlotDescription = "Reader 0", string SlotManufacturer = "Reader Co");

    private sealed class TokensModule(params Token[] tokens) : FakeModule
    {
        public int LoginCalls { get; private set; }

        protected override CKR C_GetInfo(ref CK_INFO info)
        {
            info.CryptokiVersion = new CK_VERSION { Major = 2, Minor = 40 };
            info.LibraryVersion = new CK_VERSION { Major = 2, Minor = 6 };
            NativeTestStructs.FillPadded(info.ManufacturerId, "SoftHSM");
            NativeTestStructs.FillPadded(info.LibraryDescription, "Implementation of PKCS11");
            return CKR.CKR_OK;
        }

        protected override CKR C_GetSlotList(bool tokenPresent, NativeBuffer<NativeCULong> slotList, ref NativeCULong count)
        {
            count = (NativeCULong)(ulong)tokens.Length;
            if (slotList.IsNull)
                return CKR.CKR_OK;
            for (int i = 0; i < tokens.Length; i++)
                slotList.Span[i] = (NativeCULong)tokens[i].SlotId;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetSlotInfo(NativeCULong slotId, ref CK_SLOT_INFO info)
        {
            Token? token = Find(slotId);
            if (token is null)
                return CKR.CKR_SLOT_ID_INVALID;
            NativeTestStructs.FillPadded(info.SlotDescription, token.SlotDescription);
            NativeTestStructs.FillPadded(info.ManufacturerId, token.SlotManufacturer);
            info.Flags = (NativeCULong)(ulong)CKF.CKF_TOKEN_PRESENT;
            return CKR.CKR_OK;
        }

        protected override CKR C_GetTokenInfo(NativeCULong slotId, ref CK_TOKEN_INFO info)
        {
            Token? token = Find(slotId);
            if (token is null)
                return CKR.CKR_SLOT_ID_INVALID;
            NativeTestStructs.FillPadded(info.Label, token.Label);
            NativeTestStructs.FillPadded(info.SerialNumber, token.Serial);
            NativeTestStructs.FillPadded(info.ManufacturerId, token.Manufacturer);
            NativeTestStructs.FillPadded(info.Model, token.Model);
            return CKR.CKR_OK;
        }

        protected override CKR C_Login(NativeCULong session, NativeCULong userType, ReadOnlySpan<byte> pin)
        {
            LoginCalls++;
            return CKR.CKR_OK;
        }

        private Token? Find(NativeCULong slotId) => tokens.FirstOrDefault(t => t.SlotId == (ulong)slotId);
    }

    private static TokensModule TwoSigningTokens() => new(
        new Token(3, "signing-prod", "0001", Manufacturer: "Acme", Model: "Model A"),
        new Token(9, "signing-prod", "0002", Manufacturer: "Acme", Model: "Model B", SlotDescription: "Reader 1"),
        new Token(12, "backup", "0001", Manufacturer: "Other", Model: "Model A"));

    // ---- GetSlotByTokenSerial ------------------------------------------------------------------------------------

    [Fact]
    public void Serial_SelectsTheTokenAmongSameLabels()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        Assert.Equal(new SlotId(9), library.GetSlotByTokenSerial("0002").SlotId);
        Assert.Equal(0, fake.LoginCalls);
    }

    [Fact]
    public void Serial_SharedAcrossManufacturers_IsRefused_NamingTheSlots()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<InvalidOperationException>(() => library.GetSlotByTokenSerial("0001"));

        Assert.Contains("3", ex.Message, StringComparison.Ordinal);
        Assert.Contains("12", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Serial_NoMatch_IsTokenNotPresent()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<Pkcs11TokenException>(() => library.GetSlotByTokenSerial("9999"));
        Assert.Equal(CKR.CKR_TOKEN_NOT_PRESENT, ex.ReturnValue);
    }

    [Fact]
    public void Label_Duplicated_PointsToTheSerialAndTheUri()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<InvalidOperationException>(() => library.GetSlotByTokenLabel("signing-prod"));

        Assert.Contains("GetSlotByTokenSerial", ex.Message, StringComparison.Ordinal);
        Assert.Contains("GetSlotByUri", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("by its ID", ex.Message, StringComparison.Ordinal);
    }

    // ---- FindSlot ------------------------------------------------------------------------------------------------

    [Fact]
    public void FindSlot_SeesUnpaddedFields_AndSelectsOne()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        Pkcs11Slot slot = library.FindSlot(t => t.Label == "signing-prod" && t.Model == "Model A");

        Assert.Equal(new SlotId(3), slot.SlotId);
    }

    [Fact]
    public void FindSlot_MoreThanOne_IsRefused_None_IsTokenNotPresent()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        Assert.Throws<InvalidOperationException>(() => library.FindSlot(t => t.Label == "signing-prod"));
        Assert.Throws<Pkcs11TokenException>(() => library.FindSlot(_ => false));
        Assert.Throws<ArgumentNullException>(() => library.FindSlot(null!));
    }

    [Fact]
    public void FindSlot_PredicateException_Propagates()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();
        var boom = new InvalidCastException("boom");

        Assert.Same(boom, Assert.Throws<InvalidCastException>(() => library.FindSlot(_ => throw boom)));
    }

    // ---- GetSlotByUri ----------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("pkcs11:token=signing-prod;serial=0002", 9)]
    [InlineData("PKCS11:token=signing-prod;model=Model%20A", 3)]
    [InlineData("pkcs11:token=signing-prod;slot-description=Reader%201", 9)]
    [InlineData("pkcs11:slot-id=12", 12)]
    [InlineData("pkcs11:manufacturer=Other", 12)]
    [InlineData("pkcs11:library-manufacturer=SoftHSM;library-version=2.6;token=backup", 12)]
    [InlineData("pkcs11:library-description=Implementation%20of%20PKCS11;serial=0002", 9)]
    [InlineData("pkcs11:token=backup;slot-manufacturer=Reader%20Co", 12)]
    public void Uri_SelectsTheToken(string uri, ulong slotId)
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        Assert.Equal(new SlotId(slotId), library.GetSlotByUri(uri).SlotId);
        Assert.Equal(0, fake.LoginCalls);
    }

    [Theory]
    [InlineData("pkcs11:token=signing-prod")]
    [InlineData("pkcs11:")]
    [InlineData("pkcs11:serial=0001")]
    public void Uri_NamingMoreThanOne_IsRefused(string uri)
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        Assert.Throws<InvalidOperationException>(() => library.GetSlotByUri(uri));
    }

    [Theory]
    [InlineData("pkcs11:token=nothing")]
    [InlineData("pkcs11:token=Signing-Prod;serial=0002")]  // case-sensitive
    [InlineData("pkcs11:library-version=2;token=backup")]   // 2 is 2.0, the module is 2.6
    [InlineData("pkcs11:library-manufacturer=Other;token=backup")]
    public void Uri_NamingNone_IsTokenNotPresent(string uri)
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<Pkcs11TokenException>(() => library.GetSlotByUri(uri));
        Assert.Equal(CKR.CKR_TOKEN_NOT_PRESENT, ex.ReturnValue);
    }

    [Theory]
    [InlineData("token=signing-prod", "pkcs11:")]
    [InlineData("pkcs11:token", "name=value")]
    [InlineData("pkcs11:token=signing-prod;", "name=value")]
    [InlineData("pkcs11:token=a;token=b", "more than once")]
    [InlineData("pkcs11:token=signing-prod;type=key", "'type' must be")]
    [InlineData("pkcs11:token=123456789012345678901234567890123", "longer than the 32 bytes")]
    [InlineData("pkcs11:serial=12345678901234567", "longer than the 16 bytes")]
    [InlineData("pkcs11:token=%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9%C3%A9", "longer than the 32 bytes")]
    [InlineData("pkcs11:token=signing-prod;x-vendor=1", "refused rather than ignored")]
    [InlineData("pkcs11:token=signing-prod;Token=x", "refused rather than ignored")]
    [InlineData("pkcs11:token=signing prod", "percent-encoded")]
    [InlineData("pkcs11:token=signing%2", "two hexadecimal digits")]
    [InlineData("pkcs11:token=%ff%fe", "UTF-8")]
    [InlineData("pkcs11:slot-id=-1", "decimal number")]
    [InlineData("pkcs11:slot-id=99999999999999999999999", "decimal number")]
    [InlineData("pkcs11:library-version=2.x", "major.minor")]
    [InlineData("pkcs11:library-version=256", "major.minor")]
    [InlineData("pkcs11:token=signing-prod?module-path=/usr/lib/softhsm/libsofthsm2.so", "never loads a module")]
    [InlineData("pkcs11:token=signing-prod?module-name=softhsm2", "never loads a module")]
    [InlineData("pkcs11:token=signing-prod?x-vendor=1", "query attributes")]
    public void Uri_Malformed_IsRefused_NamingWhy(string uri, string why)
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<ArgumentException>(() => library.GetSlotByUri(uri));

        Assert.Equal("uri", ex.ParamName);
        Assert.Contains(why, ex.Message, StringComparison.Ordinal);
    }

    // A PIN in a URI is refused, and never echoed: messages name the attribute, not its value.
    [Theory]
    [InlineData("pkcs11:token=signing-prod?pin-value=123456", "pin-value")]
    [InlineData("pkcs11:token=signing-prod?pin-source=file:/run/secret-123456", "pin-source")]
    public void Uri_WithAPin_IsRefused_WithoutEchoingIt(string uri, string attribute)
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        var ex = Assert.Throws<ArgumentException>(() => library.GetSlotByUri(uri));

        Assert.Contains(attribute, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("123456", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, fake.LoginCalls);
    }

    // The object attributes do not take part in selecting the token: a key's URI finds the token the key is on.
    [Fact]
    public void Uri_ObjectAttributes_SelectTheTokenTheyAreOn()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        Pkcs11Slot slot = library.GetSlotByUri("pkcs11:token=signing-prod;serial=0002;object=release-key;type=private;id=%01%02");

        Assert.Equal(new SlotId(9), slot.SlotId);
    }

    // A token's URI, from the slot, finds the slot again: the serial number tells apart the tokens sharing a label.
    [Fact]
    public void GetTokenUri_FindsTheSlotAgain()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();
        Pkcs11Slot slot = library.GetSlotByTokenSerial("0002");

        Pkcs11Uri uri = slot.GetTokenUri();

        Assert.Equal("pkcs11:manufacturer=Acme;model=Model%20B;serial=0002;token=signing-prod", uri.ToString());
        Assert.Equal(slot.SlotId, library.GetSlotByUri(uri).SlotId);
        Assert.Equal(slot.SlotId, library.GetSlotByUri(uri.ToString()).SlotId);
    }

    [Fact]
    public void Uri_PercentEncodedUtf8_Matches()
    {
        using var fake = new TokensModule(new Token(4, "clé-signature", "0042"));
        using Pkcs11Library library = fake.Load();

        Assert.Equal(new SlotId(4), library.GetSlotByUri("pkcs11:token=cl%C3%A9-signature").SlotId);
    }

    [Fact]
    public void NullArguments_Throw()
    {
        using TokensModule fake = TwoSigningTokens();
        using Pkcs11Library library = fake.Load();

        Assert.Throws<ArgumentNullException>(() => library.GetSlotByUri((string)null!));
        Assert.Throws<ArgumentNullException>(() => library.GetSlotByUri((Pkcs11Uri)null!));
        Assert.Throws<ArgumentNullException>(() => library.GetSlotByTokenSerial(null!));
    }

    [Fact]
    public void DisposedLibrary_Throws()
    {
        using TokensModule fake = TwoSigningTokens();
        Pkcs11Library library = fake.Load();
        library.Dispose();

        Assert.Throws<ObjectDisposedException>(() => library.GetSlotByTokenSerial("0002"));
        Assert.Throws<ObjectDisposedException>(() => library.FindSlot(_ => true));
        Assert.Throws<ObjectDisposedException>(() => library.GetSlotByUri("pkcs11:serial=0002"));
    }
}
