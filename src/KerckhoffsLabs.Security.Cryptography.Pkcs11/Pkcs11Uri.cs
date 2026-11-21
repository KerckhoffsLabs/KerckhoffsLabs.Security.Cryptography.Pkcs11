using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

/// <summary>
/// A PKCS#11 URI (RFC 7512) that selects a token, and optionally an object on it: for instance
/// <c>pkcs11:token=signing-prod;serial=0123456789abcdef</c>, or
/// <c>pkcs11:token=signing-prod;object=release-key;type=private</c>. An attribute it leaves out matches anything.
/// </summary>
/// <remarks>
/// <para>
/// Used with <see cref="Pkcs11Library.GetSlotByUri(Pkcs11Uri)"/> for the token, and with
/// <see cref="Pkcs11Session.OpenKey(Pkcs11Uri)"/> and <see cref="Pkcs11Session.OpenCertificate(Pkcs11Uri)"/> for an
/// object. <see cref="Pkcs11Slot.GetTokenUri"/> makes the URI of a token, to put in configuration; set the object
/// properties on a copy (<c>with</c>, or an object initializer) to name a key on it.
/// </para>
/// <para>
/// The path attributes taken: <c>token</c>, <c>manufacturer</c>, <c>serial</c>, <c>model</c> (the token);
/// <c>slot-description</c>, <c>slot-manufacturer</c>, <c>slot-id</c> (the slot); <c>library-description</c>,
/// <c>library-manufacturer</c>, <c>library-version</c> (the module); <c>object</c>, <c>type</c>, <c>id</c> (an object:
/// its <c>CKA_LABEL</c>, its class, its <c>CKA_ID</c>). Values are percent-decoded, read as UTF-8 (<c>id</c> as raw
/// bytes), and compared ordinally with the fields of <c>CK_INFO</c>, <c>CK_SLOT_INFO</c> and <c>CK_TOKEN_INFO</c> with
/// their padding removed: trailing blanks and NULs are padding in those fixed-length fields, so a value for one of them
/// (every text attribute but <c>object</c>) is stored without them, parsed or set in code: <c>token=abc%20</c> is
/// <c>token=abc</c>, names the token labelled <c>abc</c>, and is the same URI. <c>object</c> is kept exactly, as
/// <c>CKA_LABEL</c> is not padded. A value longer, once unpadded, than the field it is compared with (32 bytes for a
/// label, 16 for a serial number or model, 64 for a slot description) can match nothing, and is refused. Attribute
/// names are case-insensitive (RFC 5234 quoted strings) and written in lower case. Attribute values, <c>type</c>'s among
/// them, are compared as they are (RFC 7512 section 2.6: a simple string comparison, after RFC 3986's case
/// normalization, which lowers no value): <c>type=Private</c> names no type, and is refused. A value set in code must be valid
/// UTF-16 (no unpaired surrogate), as a parsed one must be valid UTF-8: either could not round-trip through the text.
/// </para>
/// <para>
/// Read strictly, as a selector that decides which token and key an application uses: a URI that is malformed or
/// repeats an attribute is refused, and so is any path attribute this type does not take, rather than ignored, which
/// would select more than its author meant: vendor attributes (<c>x-…</c>) and unknown ones. Query attributes do not
/// select (RFC 7512 section 2.4), so unknown ones are ignored, as the RFC asks. A URI only selects: the library never
/// takes a PIN from one (<c>pin-value</c>, <c>pin-source</c>), and a URI that carries either is refused; read the PIN
/// from a secret store and pass it to <see cref="Pkcs11Slot.Login(TokenUser, SecurePin)"/>. Nor does it load a module from one
/// (<c>module-name</c>, <c>module-path</c>, also refused): the module is the one the <see cref="Pkcs11Library"/> was
/// loaded from.
/// Error messages name the attribute at fault, never the URI's values, which may carry a PIN; an unknown path attribute
/// is given by its position, not its name, which may be a mistyped secret.
/// </para>
/// </remarks>
public sealed record Pkcs11Uri
{
    private const string Scheme = "pkcs11:";

    // The RFC 7512 path attribute names.
    private const string TokenAttribute = "token";
    private const string ManufacturerAttribute = "manufacturer";
    private const string SerialAttribute = "serial";
    private const string ModelAttribute = "model";
    private const string SlotDescriptionAttribute = "slot-description";
    private const string SlotManufacturerAttribute = "slot-manufacturer";
    private const string SlotIdAttribute = "slot-id";
    private const string LibraryDescriptionAttribute = "library-description";
    private const string LibraryManufacturerAttribute = "library-manufacturer";
    private const string LibraryVersionAttribute = "library-version";
    private const string ObjectAttribute = "object";
    private const string TypeAttribute = "type";
    private const string IdAttribute = "id";

    // Field sizes in CK_TOKEN_INFO, CK_SLOT_INFO and CK_INFO (PKCS#11 v3.2): a longer value can match nothing.
    private const int LabelLength = 32;
    private const int SerialLength = 16;
    private const int SlotDescriptionLength = 64;

    private readonly string? _token;
    private readonly string? _manufacturer;
    private readonly string? _serial;
    private readonly string? _model;
    private readonly string? _slotDescription;
    private readonly string? _slotManufacturer;
    private readonly string? _libraryDescription;
    private readonly string? _libraryManufacturer;
    private readonly string? _object;
    private readonly byte[]? _id;

    /// <summary>
    /// The token label (<c>token</c>), at most 32 UTF-8 bytes, without its padding: trailing blanks and NULs set are
    /// removed, as they pad the <c>CK_TOKEN_INFO</c> field.
    /// </summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not valid UTF-16.</exception>
    public string? Token { get => _token; init => _token = Checked(Unpadded(value), TokenAttribute, LabelLength); }

    /// <summary>The token's manufacturer (<c>manufacturer</c>), at most 32 UTF-8 bytes, without trailing blanks and NULs.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not valid UTF-16.</exception>
    public string? Manufacturer { get => _manufacturer; init => _manufacturer = Checked(Unpadded(value), ManufacturerAttribute, LabelLength); }

    /// <summary>
    /// The token's serial number (<c>serial</c>), at most 16 printable ASCII characters, without trailing blanks and
    /// NULs (removed before the value is checked).
    /// </summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not printable ASCII.</exception>
    public string? Serial { get => _serial; init => _serial = CheckedSerial(Checked(Unpadded(value), SerialAttribute, SerialLength)); }

    /// <summary>The token's model (<c>model</c>), at most 16 UTF-8 bytes, without trailing blanks and NULs.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not valid UTF-16.</exception>
    public string? Model { get => _model; init => _model = Checked(Unpadded(value), ModelAttribute, SerialLength); }

    /// <summary>The slot's description (<c>slot-description</c>), at most 64 UTF-8 bytes, without trailing blanks and NULs.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not valid UTF-16.</exception>
    public string? SlotDescription
    {
        get => _slotDescription;
        init => _slotDescription = Checked(Unpadded(value), SlotDescriptionAttribute, SlotDescriptionLength);
    }

    /// <summary>The slot's manufacturer (<c>slot-manufacturer</c>), at most 32 UTF-8 bytes, without trailing blanks and NULs.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not valid UTF-16.</exception>
    public string? SlotManufacturer
    {
        get => _slotManufacturer;
        init => _slotManufacturer = Checked(Unpadded(value), SlotManufacturerAttribute, LabelLength);
    }

    /// <summary>
    /// The slot ID (<c>slot-id</c>). The module assigns it and may renumber it between runs: prefer the token's own
    /// attributes in configuration.
    /// </summary>
    /// <exception cref="ArgumentException">Set, on Windows, to a value wider than 32 bits: a <c>CK_SLOT_ID</c> is a
    /// 32-bit <c>CK_ULONG</c> there.</exception>
    public SlotId? SlotId
    {
        get;
        init => field = value is { } id && OperatingSystem.IsWindows() && id.Value > uint.MaxValue
            ? throw new ArgumentException("'slot-id' is wider than a CK_SLOT_ID on Windows (32 bits).", nameof(SlotId))
            : value;
    }

    /// <summary>The module's description (<c>library-description</c>), at most 32 UTF-8 bytes, without trailing blanks and NULs.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not valid UTF-16.</exception>
    public string? LibraryDescription
    {
        get => _libraryDescription;
        init => _libraryDescription = Checked(Unpadded(value), LibraryDescriptionAttribute, LabelLength);
    }

    /// <summary>The module's manufacturer (<c>library-manufacturer</c>), at most 32 UTF-8 bytes, without trailing blanks and NULs.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field, or that is not valid UTF-16.</exception>
    public string? LibraryManufacturer
    {
        get => _libraryManufacturer;
        init => _libraryManufacturer = Checked(Unpadded(value), LibraryManufacturerAttribute, LabelLength);
    }

    /// <summary>
    /// The module's version (<c>library-version</c>): major and minor, each 0 to 255 (<c>CK_VERSION</c>). Written
    /// "major" or "major.minor"; a missing minor is 0, so <c>2</c> is 2.0, and <c>2.40</c> is 2.40.
    /// </summary>
    /// <exception cref="ArgumentException">Set to a version whose major or minor is above 255, or that has a build or revision.</exception>
    public Version? LibraryVersion
    {
        get;
        init => field = value is null || (value.Major <= byte.MaxValue && value.Minor <= byte.MaxValue && value.Build < 0
            && value.Revision < 0)
            ? value
            : throw new ArgumentException("'library-version' is a CK_VERSION: a major and a minor from 0 to 255, nothing more.",
                nameof(LibraryVersion));
    }

    /// <summary>
    /// The object's label (<c>object</c>, its <c>CKA_LABEL</c>), kept exactly: <c>CKA_LABEL</c> is variable-length, not
    /// padded, so a trailing blank or NUL is part of it.
    /// </summary>
    /// <exception cref="ArgumentException">Set to a value that is not valid UTF-16.</exception>
    public string? Object { get => _object; init => _object = Checked(value, ObjectAttribute, int.MaxValue); }

    /// <summary>
    /// The object's class (<c>type</c>): <see cref="CKO.CKO_PUBLIC_KEY"/> (<c>public</c>),
    /// <see cref="CKO.CKO_PRIVATE_KEY"/> (<c>private</c>), <see cref="CKO.CKO_CERTIFICATE"/> (<c>cert</c>),
    /// <see cref="CKO.CKO_SECRET_KEY"/> (<c>secret-key</c>) or <see cref="CKO.CKO_DATA"/> (<c>data</c>).
    /// </summary>
    /// <exception cref="ArgumentException">Set to a class RFC 7512 has no name for.</exception>
    public CKO? Type
    {
        get;
        init => field = value is null || TypeName(value.Value) is not null
            ? value
            : throw new ArgumentException($"RFC 7512 has no 'type' for {value}.", nameof(Type));
    }

    /// <summary>The object's <c>CKA_ID</c> (<c>id</c>), or <see langword="null"/> when the URI does not name one.</summary>
    public ReadOnlyMemory<byte>? Id
    {
        // Not a conditional: the null literal converts to ReadOnlyMemory<byte> through byte[] (empty, not null).
        get
        {
            if (_id is null)
                return null;
            // A copy: the caller cannot change this URI's id, its text, or its equality.
            return new ReadOnlyMemory<byte>([.. _id]);
        }
        init => _id = value?.ToArray();
    }

    /// <summary>Whether the URI says anything about the module (a <c>library-*</c> attribute).</summary>
    public bool NamesLibrary => LibraryDescription is not null || LibraryManufacturer is not null || LibraryVersion is not null;

    /// <summary>Whether the URI says anything about an object (<c>object</c>, <c>type</c> or <c>id</c>).</summary>
    public bool NamesObject => Object is not null || Type is not null || _id is not null;

    /// <summary>Whether the URI says anything about the token (<c>token</c>, <c>manufacturer</c>, <c>serial</c>, <c>model</c>).</summary>
    public bool NamesToken => Token is not null || Manufacturer is not null || Serial is not null || Model is not null;

    /// <summary>Whether the URI says anything about the slot (<c>slot-description</c>, <c>slot-manufacturer</c>, <c>slot-id</c>).</summary>
    public bool NamesSlot => NamesSlotInfo || SlotId is not null;

    /// <summary>Parses <paramref name="uri"/>. See the remarks of <see cref="Pkcs11Uri"/> for what is taken.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">
    /// It is not a PKCS#11 URI this type takes: the message names what is wrong, never the URI's values.
    /// </exception>
    public static Pkcs11Uri Parse(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return ParseCore(uri, out string? error) ?? throw new FormatException(error);
    }

    /// <summary>Parses <paramref name="uri"/>; <see langword="false"/> when it is not a PKCS#11 URI this type takes.</summary>
    public static bool TryParse([NotNullWhen(true)] string? uri, [NotNullWhen(true)] out Pkcs11Uri? result)
    {
        result = uri is null ? null : ParseCore(uri, out _);
        return result is not null;
    }

    /// <summary>
    /// The URI's canonical text: every attribute it has, in a fixed order (module, slot, token, object), values
    /// percent-encoded where RFC 7512 requires it, the <c>id</c> fully.
    /// </summary>
    public override string ToString()
    {
        var text = new StringBuilder(Scheme);
        bool first = true;
        void Add(string name, string? value)
        {
            if (value is null)
                return;
            if (!first)
                text.Append(';');
            first = false;
            text.Append(name).Append('=').Append(value);
        }

        Add(LibraryManufacturerAttribute, Encode(LibraryManufacturer));
        Add(LibraryDescriptionAttribute, Encode(LibraryDescription));
        Add(LibraryVersionAttribute, LibraryVersion is null ? null
            : string.Create(CultureInfo.InvariantCulture, $"{LibraryVersion.Major}.{LibraryVersion.Minor}"));
        Add(SlotManufacturerAttribute, Encode(SlotManufacturer));
        Add(SlotDescriptionAttribute, Encode(SlotDescription));
        Add(SlotIdAttribute, SlotId?.Value.ToString(CultureInfo.InvariantCulture));
        Add(ManufacturerAttribute, Encode(Manufacturer));
        Add(ModelAttribute, Encode(Model));
        Add(SerialAttribute, Encode(Serial));
        Add(TokenAttribute, Encode(Token));
        Add(ObjectAttribute, Encode(Object));
        Add(TypeAttribute, Type is { } type ? TypeName(type) : null);
        Add(IdAttribute, _id is null ? null : string.Concat(_id.Select(b => "%" + b.ToString("X2", CultureInfo.InvariantCulture))));
        return text.ToString();
    }

    /// <summary>
    /// Whether <paramref name="other"/> is the same URI: the same canonical text (<see cref="ToString"/>). The token,
    /// slot and library values are compared without their padding (<c>pkcs11:token=abc</c> equals
    /// <c>pkcs11:token=abc%20</c>), as they are stored without it; <c>object</c> is compared exactly.
    /// </summary>
    public bool Equals(Pkcs11Uri? other) => other is not null && string.Equals(ToString(), other.ToString(), StringComparison.Ordinal);

    /// <inheritdoc/>
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(ToString());

    /// <summary>
    /// Whether the URI names the module <paramref name="info"/> describes, and nothing else this cannot check: a URI
    /// that also names the slot (<c>slot-*</c>) or the token (<c>token</c>, <c>manufacturer</c>, <c>serial</c>,
    /// <c>model</c>) matches no <see cref="LibraryInfo"/> on its own, as ignoring those attributes would select more than
    /// the URI names. The object attributes do not select a module, slot or token, and are not considered. Use
    /// <see cref="Matches(Pkcs11Slot)"/> for the whole URI.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="info"/> is <see langword="null"/>.</exception>
    public bool Matches(LibraryInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return !NamesSlot && !NamesToken && MatchesLibrary(info);
    }

    /// <summary>
    /// Whether the URI names the slot <paramref name="info"/> describes (<c>slot-description</c>,
    /// <c>slot-manufacturer</c>, <c>slot-id</c>), and nothing else this cannot check: a URI that also names the token or
    /// the module (<c>library-*</c>) matches no <see cref="SlotInfo"/> on its own. The object attributes are not
    /// considered. Use <see cref="Matches(Pkcs11Slot)"/> for the whole URI.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="info"/> is <see langword="null"/>.</exception>
    public bool Matches(SlotInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return !NamesToken && !NamesLibrary && MatchesSlot(info);
    }

    /// <summary>
    /// Whether the URI names the token <paramref name="info"/> describes (<c>token</c>, <c>manufacturer</c>,
    /// <c>serial</c>, <c>model</c>, and <c>slot-id</c> against <see cref="TokenInfo.SlotId"/>), and nothing else this
    /// cannot check: a URI that also names the slot's description or manufacturer, or the module, matches no
    /// <see cref="TokenInfo"/> on its own. The object attributes are not considered. Use
    /// <see cref="Matches(Pkcs11Slot)"/> for the whole URI.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="info"/> is <see langword="null"/>.</exception>
    public bool Matches(TokenInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return !NamesSlotInfo && !NamesLibrary && MatchesToken(info);
    }

    /// <summary>
    /// Whether the token in <paramref name="slot"/> is one the whole URI names: its module (<c>library-*</c>, from
    /// <see cref="Pkcs11Library.GetInfo"/>), its slot (<c>slot-*</c>) and its token attributes. Queries the module. The
    /// object attributes do not select a token, and are not considered.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="slot"/> is <see langword="null"/>.</exception>
    /// <exception cref="Exceptions.Pkcs11Exception">Propagated from <c>C_GetInfo</c>, <c>C_GetSlotInfo</c> or <c>C_GetTokenInfo</c>.</exception>
    public bool Matches(Pkcs11Slot slot)
    {
        ArgumentNullException.ThrowIfNull(slot);
        return (!NamesLibrary || MatchesLibrary(slot.Library.GetInfo())) && Matches(slot, slot.GetTokenInfo());
    }

    // The per-part checks: each looks only at the attributes of its part, and the callers combine them so that every
    // attribute the URI names is checked by one of them. Lookups use these, never the public overloads, which refuse a
    // URI naming more than their argument shows.
    internal bool MatchesLibrary(LibraryInfo info)
        => Same(LibraryDescription, info.RawLibraryDescription)
            && Same(LibraryManufacturer, info.RawManufacturerId)
            && (LibraryVersion is null
                || (LibraryVersion.Major == info.LibraryVersion.Major && LibraryVersion.Minor == info.LibraryVersion.Minor));

    private bool MatchesSlot(SlotInfo info)
        => Same(SlotDescription, info.RawSlotDescription)
            && Same(SlotManufacturer, info.RawManufacturerId)
            && (SlotId is null || SlotId == info.SlotId);

    private bool MatchesToken(TokenInfo info)
        => Same(Token, info.RawLabel)
            && Same(Manufacturer, info.RawManufacturerId)
            && Same(Serial, info.RawSerialNumber)
            && Same(Model, info.RawModel)
            && (SlotId is null || SlotId == info.SlotId);

    // Whether the URI needs the slot's CK_SLOT_INFO to be checked (a slot-id is checked against the token's).
    internal bool NamesSlotInfo => SlotDescription is not null || SlotManufacturer is not null;

    // The slot and token half of a selection (the module is checked once, by the caller): the token attributes, and
    // the slot attributes against slotInfo, which the caller reads when NamesSlotInfo; null then matches nothing.
    internal bool Matches(TokenInfo token, SlotInfo? slotInfo)
        => MatchesToken(token) && (!NamesSlotInfo || (slotInfo is not null && MatchesSlot(slotInfo)));

    // As above, reading the slot's CK_SLOT_INFO from slot when the URI needs it.
    internal bool Matches(Pkcs11Slot slot, TokenInfo token)
        => Matches(token, NamesSlotInfo ? slot.GetSlotInfo() : null);

    /// <summary>
    /// The URI of the token <paramref name="info"/> describes: its manufacturer, model, serial number and label, each
    /// exactly but for its padding (an empty field as an empty value, which matches only an empty field).
    /// </summary>
    /// <exception cref="Exceptions.Pkcs11TokenException">
    /// <see cref="CKR.CKR_TOKEN_NOT_RECOGNIZED"/>: the module reported a field whose bytes are not UTF-8 (or, for the
    /// serial number, not printable ASCII once its padding is removed). No URI value names it, and leaving it out would
    /// name every token that shares the other fields.
    /// </exception>
    internal static Pkcs11Uri ForToken(TokenInfo info) => new()
    {
        Manufacturer = Exact(info.ManufacturerId, info.RawManufacturerId, ManufacturerAttribute, "manufacturer ID"),
        Model = Exact(info.Model, info.RawModel, ModelAttribute, "model"),
        Serial = IsPrintableAscii(info.RawSerialNumber)
            ? Exact(info.SerialNumber, info.RawSerialNumber, SerialAttribute, "serial number")
            : throw Unnamable(SerialAttribute, "serial number", "is not printable ASCII"),
        Token = Exact(info.Label, info.RawLabel, TokenAttribute, "label"),
    };

    // Trailing blanks and NULs are padding in a fixed-length PKCS#11 field. The wanted value is stored without them
    // (Unpadded), and compared as UTF-8 bytes with the field's bytes, padding removed (PaddedField.Raw): a field that is
    // not UTF-8 matches no value, where its decoded text (U+FFFD for each bad byte) could match one.
    private static bool Same(string? wanted, string raw)
        => wanted is null || string.Equals(Internal.PaddedField.RawOf(wanted), raw, StringComparison.Ordinal);

    // A value for a fixed-length, blank-padded PKCS#11 field (CK_UTF8CHAR or CK_CHAR in CK_TOKEN_INFO, CK_SLOT_INFO,
    // CK_INFO), canonical: its trailing blanks and NULs are padding, not part of it, so "abc " is "abc" for matching,
    // for the length and printable checks, for the text and for equality. Not for object: CKA_LABEL is not padded.
    private static string? Unpadded(string? value) => value?.TrimEnd(' ', '\0');

    // A value set in code: valid UTF-16 (an unpaired surrogate would encode to U+FFFD, so two different values would
    // share a text and an equality) and no longer than the field it is compared with.
    private static string? Checked(string? value, string name, int maxBytes,
        [System.Runtime.CompilerServices.CallerMemberName] string property = "")
    {
        if (value is null)
            return null;
        int bytes;
        try
        {
            bytes = StrictUtf8.GetByteCount(value);
        }
        catch (EncoderFallbackException)
        {
            throw new ArgumentException($"'{name}' is not valid UTF-16 (it has an unpaired surrogate): no URI can carry it.",
                property);
        }
        if (bytes > maxBytes)
        {
            throw new ArgumentException(
                $"'{name}' is longer than the {maxBytes} bytes the PKCS#11 field it is compared with holds: it can match nothing.",
                property);
        }
        return value;
    }

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    // A serial number is a CK_CHAR field (PKCS#11 v3.2 CK_TOKEN_INFO), printable ASCII: anything else matches nothing.
    private static string? CheckedSerial(string? value, [System.Runtime.CompilerServices.CallerMemberName] string property = "")
    {
        if (value is not null && !IsPrintableAscii(value))
            throw new ArgumentException("'serial' must be printable ASCII, as the PKCS#11 field (CK_CHAR) is.", property);
        return value;
    }

    private static bool IsPrintableAscii(string value) => value.All(c => c is >= ' ' and <= '~');

    // A field as the module reported it, padding removed. One whose bytes are not UTF-8 has no URI value that stands
    // for it, and leaving the field out would widen the URI to every token sharing the rest, so it is refused. Told from
    // the bytes (raw), so a field that genuinely holds U+FFFD is named.
    private static string Exact(string value, string raw, string name, string field)
        => Internal.PaddedField.IsUtf8(raw) ? value : throw Unnamable(name, field, "is not UTF-8");

    // What the token reported, not a misuse of the API: a Pkcs11TokenException, as for a token the library cannot work
    // with. Named after C_GetTokenInfo, which reported the field.
    private static Exceptions.Pkcs11TokenException Unnamable(string name, string field, string why)
        => new(CKR.CKR_TOKEN_NOT_RECOGNIZED, Internal.Pkcs11Operations.OpGetTokenInfo,
            $"The token's {field} {why}: no PKCS#11 URI value ('{name}') names it, and a URI without it could select " +
            "another token. Select the token with Pkcs11Library.GetSlot (a predicate on its TokenInfo) instead.");

    private static string? TypeName(CKO type) => type switch
    {
        CKO.CKO_PUBLIC_KEY => "public",
        CKO.CKO_PRIVATE_KEY => "private",
        CKO.CKO_CERTIFICATE => "cert",
        CKO.CKO_SECRET_KEY => "secret-key",
        CKO.CKO_DATA => "data",
        _ => null,
    };

    private static readonly HashSet<string> Taken = new(StringComparer.Ordinal)
    {
        TokenAttribute, ManufacturerAttribute, SerialAttribute, ModelAttribute,
        SlotDescriptionAttribute, SlotManufacturerAttribute, SlotIdAttribute,
        LibraryDescriptionAttribute, LibraryManufacturerAttribute, LibraryVersionAttribute,
        ObjectAttribute, TypeAttribute, IdAttribute,
    };

    // Null with error set when uri is not one this type takes. Errors name the attribute, never a value. The parse
    // reports a failure as UriFormatException, which nothing else in it throws.
    private static Pkcs11Uri? ParseCore(string uri, out string? error)
    {
        try
        {
            error = null;
            return ParseOrThrow(uri);
        }
        catch (UriFormatException ex)
        {
            error = $"Not a PKCS#11 URI (RFC 7512) this library takes: {ex.Message}";
            return null;
        }
    }

    private static Pkcs11Uri ParseOrThrow(string uri)
    {
        if (!uri.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
            throw new UriFormatException("it does not start with \"pkcs11:\".");

        string rest = uri[Scheme.Length..];
        int query = rest.IndexOf('?', StringComparison.Ordinal);
        if (query >= 0)
            CheckQuery(rest[(query + 1)..]);
        string path = query >= 0 ? rest[..query] : rest;

        var values = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (path.Length > 0)
        {
            string[] attributes = path.Split(';');
            for (int position = 1; position <= attributes.Length; position++)
            {
                string attribute = attributes[position - 1];
                int equals = attribute.IndexOf('=', StringComparison.Ordinal);
                if (equals <= 0)
                    throw new UriFormatException("every path attribute must read name=value, separated by ';'.");
                // Attribute names are case-insensitive (RFC 5234): "Token" is "token", and repeats it.
                string name = AsciiLower(attribute[..equals]);
                ThrowIfNotTaken(name, position);
                if (!values.TryAdd(name, Decode(name, attribute[(equals + 1)..])))
                    throw new UriFormatException($"the attribute '{name}' appears more than once.");
            }
        }

        return new Pkcs11Uri
        {
            Token = Text(values, TokenAttribute),
            Manufacturer = Text(values, ManufacturerAttribute),
            Serial = Text(values, SerialAttribute),
            Model = Text(values, ModelAttribute),
            SlotDescription = Text(values, SlotDescriptionAttribute),
            SlotManufacturer = Text(values, SlotManufacturerAttribute),
            SlotId = Text(values, SlotIdAttribute) is { } slotId ? ParseSlotId(slotId) : null,
            LibraryDescription = Text(values, LibraryDescriptionAttribute),
            LibraryManufacturer = Text(values, LibraryManufacturerAttribute),
            LibraryVersion = Text(values, LibraryVersionAttribute) is { } version ? ParseVersion(version) : null,
            Object = Text(values, ObjectAttribute),
            Type = Text(values, TypeAttribute) is { } type ? ParseType(type) : null,
            Id = IdOf(values),
        };
    }

    private static readonly Dictionary<string, int> FieldBytes = new(StringComparer.Ordinal)
    {
        [TokenAttribute] = LabelLength,
        [ManufacturerAttribute] = LabelLength,
        [SerialAttribute] = SerialLength,
        [ModelAttribute] = SerialLength,
        [SlotDescriptionAttribute] = SlotDescriptionLength,
        [SlotManufacturerAttribute] = LabelLength,
        [LibraryDescriptionAttribute] = LabelLength,
        [LibraryManufacturerAttribute] = LabelLength,
    };

    // Not a conditional, for the reason the Id getter gives.
    private static ReadOnlyMemory<byte>? IdOf(Dictionary<string, byte[]> values)
    {
        if (!values.TryGetValue(IdAttribute, out byte[]? id))
            return null;
        return id;
    }

    private static string? Text(Dictionary<string, byte[]> values, string name)
    {
        if (!values.TryGetValue(name, out byte[]? bytes))
            return null;
        // A padded field's value loses its padding before it is checked, as the setter would: token=<32 bytes>%20 fits
        // the 32-byte label, and serial=abc%00 is the printable serial abc. A blank and a NUL are single bytes in UTF-8,
        // never part of a longer sequence, so trimming the bytes trims the text.
        bool padded = FieldBytes.TryGetValue(name, out int max);
        if (padded)
            bytes = bytes.AsSpan().TrimEnd(" \0"u8).ToArray();
        if (padded && bytes.Length > max)
        {
            throw new UriFormatException(
                $"'{name}' is longer than the {max} bytes the PKCS#11 field it is compared with holds: it can match nothing.");
        }
        if (name == SerialAttribute && !bytes.All(b => b is >= 0x20 and <= 0x7E))
            throw new UriFormatException("'serial' must be printable ASCII, as the PKCS#11 field (CK_CHAR) is.");
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new UriFormatException($"the value of '{name}' does not decode to UTF-8.");
        }
    }

    // position is the attribute's 1-based index among the path attributes. Its name is not echoed: a URI mistyped in
    // configuration (pkcs11:mysecretpin1234=… for a pin-value) may carry a secret where a name should be, and a name
    // could also forge a log line. The position says which one is at fault without repeating it.
    private static void ThrowIfNotTaken(string name, int position)
    {
        if (Taken.Contains(name))
            return;
        throw new UriFormatException(string.Create(CultureInfo.InvariantCulture,
            $"the path attribute at position {position} is an unknown path attribute: not one this library takes ") +
            "(token, manufacturer, serial, model, slot-description, slot-manufacturer, slot-id, library-description, " +
            "library-manufacturer, " +
            "library-version, object, type, id). It is refused rather than ignored, which could select something else.");
    }

    // RFC 7512 section 2.4: query attributes do not select. Unknown ones are ignored (section 2.5) and so is an empty
    // query; the ones that would hand the library a PIN or a module are refused, as the library never takes either from
    // a URI. The query is read to the grammar first: each attribute name=value, the name of letters, digits, '-' and
    // '_', the value of pk11-qchar. Otherwise a pin-value could hide behind a character the split does not expect
    // (?x=1;pin-value=…, ?pin-value =…) or a fragment (?x#pin-value=…).
    private static void CheckQuery(string query)
    {
        if (query.Length == 0)
            return;
        // Only the names are looked at: a pin-value must not reach a message. They are compared ignoring case, so
        // PIN-VALUE is refused like pin-value; the message names the canonical attribute, never what the URI spelled.
        foreach (string attribute in query.Split('&'))
        {
            int equals = attribute.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
                throw new UriFormatException("every query attribute must read name=value, separated by '&'.");
            string name = attribute[..equals];
            if (!name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
                throw new UriFormatException("a query attribute has a name that is not a valid attribute name.");
            string? pin = Refused(name, "pin-value", "pin-source");
            if (pin is not null)
            {
                throw new UriFormatException($"it carries '{pin}': the library never takes a PIN from a URI. Read the PIN " +
                    "from a secret store and pass it to Pkcs11Slot.Login.");
            }
            string? module = Refused(name, "module-name", "module-path");
            if (module is not null)
            {
                throw new UriFormatException($"it carries '{module}': the library never loads a module from a URI. The module " +
                    "is the one Pkcs11Library.Load loaded.");
            }
            if (!IsQueryValue(attribute.AsSpan(equals + 1)))
            {
                throw new UriFormatException("a query attribute's value has a character that must be percent-encoded, " +
                    "or a '%' not followed by two hexadecimal digits.");
            }
        }

        static string? Refused(string name, string first, string second)
        {
            if (Ascii.EqualsIgnoreCase(name, first))
                return first;
            return Ascii.EqualsIgnoreCase(name, second) ? second : null;
        }
    }

    // RFC 7512 pk11-qchar: unreserved, percent-encoded, and ":[]@!$'()*+,=/?|". Not ';', '&' (it separates attributes)
    // nor '#' (a fragment).
    private static bool IsQueryValue(ReadOnlySpan<char> value)
    {
        int i = 0;
        while (i < value.Length)
        {
            char c = value[i];
            if (c == '%')
            {
                if (i + 2 >= value.Length || !char.IsAsciiHexDigit(value[i + 1]) || !char.IsAsciiHexDigit(value[i + 2]))
                    return false;
                i += 3;
                continue;
            }
            if (!IsUnreserved(c) && c is not (':' or '[' or ']' or '@' or '!' or '$' or '\'' or '(' or ')' or '*'
                    or '+' or ',' or '=' or '/' or '?' or '|'))
            {
                return false;
            }
            i++;
        }
        return true;
    }

    // ASCII letters lowered, anything else left as it is: RFC 5234 case-insensitivity covers ASCII only, so a non-ASCII
    // name or type (a Kelvin sign for 'k') is not folded onto a known one.
    private static string AsciiLower(string value)
    {
        if (!value.Any(char.IsAsciiLetterUpper))
            return value;
        return string.Create(value.Length, value, static (span, source) =>
        {
            for (int i = 0; i < source.Length; i++)
                span[i] = char.IsAsciiLetterUpper(source[i]) ? (char)(source[i] | 0x20) : source[i];
        });
    }

    // RFC 7512 pk-pchar: unreserved, percent-encoded, and ":[]@!$'()*+,=&". Anything else (a space included) must be
    // percent-encoded; it is refused rather than guessed at.
    private static byte[] Decode(string name, string value)
    {
        var bytes = new List<byte>(value.Length);
        int i = 0;
        while (i < value.Length)
        {
            char c = value[i];
            if (c == '%')
            {
                if (i + 2 >= value.Length || !char.IsAsciiHexDigit(value[i + 1]) || !char.IsAsciiHexDigit(value[i + 2]))
                    throw new UriFormatException($"the value of '{name}' has a '%' not followed by two hexadecimal digits.");
                bytes.Add(byte.Parse(value.AsSpan(i + 1, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture));
                i += 3;
            }
            else if (IsPathChar(c))
            {
                bytes.Add((byte)c);
                i++;
            }
            else
            {
                throw new UriFormatException($"the value of '{name}' has a character that must be percent-encoded (a space is %20).");
            }
        }
        return [.. bytes];
    }

    private static bool IsPathChar(char c) => IsUnreserved(c)
        || c is ':' or '[' or ']' or '@' or '!' or '$' or '\'' or '(' or ')' or '*' or '+' or ',' or '=' or '&';

    private static bool IsUnreserved(char c) => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~';

    // Percent-encodes all but the RFC 3986 unreserved characters, so the text never needs a second look.
    private static string? Encode(string? value)
    {
        if (value is null)
            return null;
        var text = new StringBuilder(value.Length);
        foreach (byte b in Encoding.UTF8.GetBytes(value))
        {
            if (b < 0x80 && IsUnreserved((char)b))
                text.Append((char)b);
            else
                text.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return text.ToString();
    }

    private static SlotId ParseSlotId(string value)
    {
        if (value.Length == 0 || !value.All(char.IsAsciiDigit)
            || !ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong id))
        {
            throw new UriFormatException("'slot-id' must be a decimal number.");
        }
        if (OperatingSystem.IsWindows() && id > uint.MaxValue)
            throw new UriFormatException("'slot-id' is wider than a CK_SLOT_ID on Windows (32 bits).");
        return new SlotId(id);
    }

    private static Version ParseVersion(string value)
    {
        string[] parts = value.Split('.');
        byte minor = 0;
        if (parts.Length is < 1 or > 2 || parts.Any(p => p.Length == 0 || !p.All(char.IsAsciiDigit))
            || !byte.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out byte major)
            || (parts.Length == 2 && !byte.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out minor)))
        {
            throw new UriFormatException("'library-version' must read major or major.minor, each a number from 0 to 255.");
        }
        return new Version(major, minor);
    }

    // Compared as the value it is (RFC 7512 section 2.6: attribute values are compared as strings, and RFC 3986's case
    // normalization lowers no value): "Private" names no type.
    private static CKO ParseType(string value) => value switch
    {
        "public" => CKO.CKO_PUBLIC_KEY,
        "private" => CKO.CKO_PRIVATE_KEY,
        "cert" => CKO.CKO_CERTIFICATE,
        "secret-key" => CKO.CKO_SECRET_KEY,
        "data" => CKO.CKO_DATA,
        _ => throw new UriFormatException("'type' must be public, private, cert, secret-key or data."),
    };
}
