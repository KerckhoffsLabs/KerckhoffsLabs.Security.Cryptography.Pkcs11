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
/// their padding removed. A value longer than the field it is compared with (32 bytes for a label, 16 for a serial
/// number or model, 64 for a slot description) can match nothing, and is refused.
/// </para>
/// <para>
/// Read strictly, as a selector that decides which token and key an application uses: a URI that is malformed or
/// repeats an attribute is refused, and so is any attribute this type does not take, rather than ignored, which
/// would select more than its author meant: vendor attributes (<c>x-…</c>), unknown ones, and every query attribute.
/// A URI only selects. The library never takes a PIN from one (<c>pin-value</c>, <c>pin-source</c>): read the PIN
/// from a secret store and pass it to <see cref="Pkcs11Slot.Login"/>. Nor does it load a module from one
/// (<c>module-name</c>, <c>module-path</c>): the module is the one the <see cref="Pkcs11Library"/> was loaded from.
/// Error messages name the attribute at fault, never the URI's values, which may carry a PIN.
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
    private readonly byte[]? _id;

    /// <summary>The token label (<c>token</c>), at most 32 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? Token { get => _token; init => _token = Checked(value, TokenAttribute, LabelLength); }

    /// <summary>The token's manufacturer (<c>manufacturer</c>), at most 32 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? Manufacturer { get => _manufacturer; init => _manufacturer = Checked(value, ManufacturerAttribute, LabelLength); }

    /// <summary>The token's serial number (<c>serial</c>), at most 16 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? Serial { get => _serial; init => _serial = Checked(value, SerialAttribute, SerialLength); }

    /// <summary>The token's model (<c>model</c>), at most 16 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? Model { get => _model; init => _model = Checked(value, ModelAttribute, SerialLength); }

    /// <summary>The slot's description (<c>slot-description</c>), at most 64 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? SlotDescription
    {
        get => _slotDescription;
        init => _slotDescription = Checked(value, SlotDescriptionAttribute, SlotDescriptionLength);
    }

    /// <summary>The slot's manufacturer (<c>slot-manufacturer</c>), at most 32 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? SlotManufacturer
    {
        get => _slotManufacturer;
        init => _slotManufacturer = Checked(value, SlotManufacturerAttribute, LabelLength);
    }

    /// <summary>
    /// The slot ID (<c>slot-id</c>). The module assigns it and may renumber it between runs: prefer the token's own
    /// attributes in configuration.
    /// </summary>
    public ulong? SlotId { get; init; }

    /// <summary>The module's description (<c>library-description</c>), at most 32 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? LibraryDescription
    {
        get => _libraryDescription;
        init => _libraryDescription = Checked(value, LibraryDescriptionAttribute, LabelLength);
    }

    /// <summary>The module's manufacturer (<c>library-manufacturer</c>), at most 32 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">Set to a value longer than the field.</exception>
    public string? LibraryManufacturer
    {
        get => _libraryManufacturer;
        init => _libraryManufacturer = Checked(value, LibraryManufacturerAttribute, LabelLength);
    }

    /// <summary>
    /// The module's version (<c>library-version</c>): major and minor, each 0 to 255 (<c>CK_VERSION</c>). Written
    /// "major" or "major.minor"; a missing minor is 0, so <c>2</c> is 2.0, and <c>2.40</c> is 2.40.
    /// </summary>
    public Version? LibraryVersion { get; init; }

    /// <summary>The object's label (<c>object</c>, its <c>CKA_LABEL</c>).</summary>
    public string? Object { get; init; }

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
            : throw new ArgumentException($"RFC 7512 has no 'type' for {value}.", nameof(value));
    }

    /// <summary>The object's <c>CKA_ID</c> (<c>id</c>), or <see langword="null"/> when the URI does not name one.</summary>
    public ReadOnlyMemory<byte>? Id
    {
        // Not a conditional: the null literal converts to ReadOnlyMemory<byte> through byte[] (empty, not null).
        get
        {
            if (_id is null)
                return null;
            return new ReadOnlyMemory<byte>(_id);
        }
        init => _id = value?.ToArray();
    }

    /// <summary>Whether the URI says anything about the module (a <c>library-*</c> attribute).</summary>
    public bool NamesLibrary => LibraryDescription is not null || LibraryManufacturer is not null || LibraryVersion is not null;

    /// <summary>Whether the URI says anything about an object (<c>object</c>, <c>type</c> or <c>id</c>).</summary>
    public bool NamesObject => Object is not null || Type is not null || Id is not null;

    private bool NamesSlotInfo => SlotDescription is not null || SlotManufacturer is not null;

    /// <summary>Parses <paramref name="uri"/>. See the remarks of <see cref="Pkcs11Uri"/> for what is taken.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// It is not a PKCS#11 URI this type takes: the message names what is wrong, never the URI's values.
    /// </exception>
    public static Pkcs11Uri Parse(string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return ParseCore(uri, out string? error) ?? throw new ArgumentException(error, nameof(uri));
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
        Add(SlotIdAttribute, SlotId?.ToString(CultureInfo.InvariantCulture));
        Add(ManufacturerAttribute, Encode(Manufacturer));
        Add(ModelAttribute, Encode(Model));
        Add(SerialAttribute, Encode(Serial));
        Add(TokenAttribute, Encode(Token));
        Add(ObjectAttribute, Encode(Object));
        Add(TypeAttribute, Type is { } type ? TypeName(type) : null);
        Add(IdAttribute, _id is null ? null : string.Concat(_id.Select(b => "%" + b.ToString("X2", CultureInfo.InvariantCulture))));
        return text.ToString();
    }

    /// <summary>Whether <paramref name="other"/> is the same URI: the same canonical text (<see cref="ToString"/>).</summary>
    public bool Equals(Pkcs11Uri? other) => other is not null && string.Equals(ToString(), other.ToString(), StringComparison.Ordinal);

    /// <inheritdoc/>
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(ToString());

    /// <summary>Whether the module described by <paramref name="info"/> is the one the URI names.</summary>
    public bool Matches(LibraryInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return Same(LibraryDescription, info.LibraryDescription)
            && Same(LibraryManufacturer, info.ManufacturerId)
            && (LibraryVersion is null
                || (LibraryVersion.Major == info.LibraryVersion.Major && LibraryVersion.Minor == info.LibraryVersion.Minor));
    }

    /// <summary>Whether the slot described by <paramref name="info"/> is one the URI names.</summary>
    public bool Matches(SlotInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return Same(SlotDescription, info.SlotDescription)
            && Same(SlotManufacturer, info.ManufacturerId)
            && (SlotId is null || SlotId == info.SlotId.Value);
    }

    /// <summary>Whether the token described by <paramref name="info"/> is one the URI names (its slot ID included).</summary>
    public bool Matches(TokenInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return Same(Token, info.Label)
            && Same(Manufacturer, info.ManufacturerId)
            && Same(Serial, info.SerialNumber)
            && Same(Model, info.Model)
            && (SlotId is null || SlotId == info.SlotId.Value);
    }

    // The token half of a selection on slot: the token attributes, and the slot attributes when the URI has some.
    internal bool Matches(Pkcs11Slot slot, TokenInfo token)
        => Matches(token) && (!NamesSlotInfo || Matches(slot.GetSlotInfo()));

    /// <summary>The URI of the token <paramref name="info"/> describes: its manufacturer, model, serial number and label.</summary>
    internal static Pkcs11Uri ForToken(TokenInfo info) => new()
    {
        Manufacturer = Fit(info.ManufacturerId, LabelLength),
        Model = Fit(info.Model, SerialLength),
        Serial = Fit(info.SerialNumber, SerialLength),
        Token = Fit(info.Label, LabelLength),
    };

    private static bool Same(string? wanted, string actual)
        => wanted is null || string.Equals(wanted, actual.TrimEnd(' '), StringComparison.Ordinal);

    private static string? Checked(string? value, string name, int maxBytes)
    {
        if (value is not null && Encoding.UTF8.GetByteCount(value) > maxBytes)
        {
            throw new ArgumentException(
                $"'{name}' is longer than the {maxBytes} bytes the PKCS#11 field it is compared with holds: it can match nothing.",
                nameof(value));
        }
        return value;
    }

    // A field as the module reported it, padding removed. It came from a field of maxBytes, but a module's invalid
    // UTF-8 decodes to replacement characters, which take more bytes: those are cut off rather than refused.
    private static string Fit(string value, int maxBytes)
    {
        string trimmed = value.TrimEnd(' ');
        while (Encoding.UTF8.GetByteCount(trimmed) > maxBytes)
            trimmed = trimmed[..^1];
        return trimmed;
    }

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
            ThrowForQuery(rest[(query + 1)..]);
        string path = query >= 0 ? rest[..query] : rest;

        var values = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (path.Length > 0)
        {
            foreach (string attribute in path.Split(';'))
            {
                int equals = attribute.IndexOf('=', StringComparison.Ordinal);
                if (equals <= 0)
                    throw new UriFormatException("every path attribute must read name=value, separated by ';'.");
                string name = attribute[..equals];
                ThrowIfNotTaken(name);
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
        if (FieldBytes.TryGetValue(name, out int max) && bytes.Length > max)
        {
            throw new UriFormatException(
                $"'{name}' is longer than the {max} bytes the PKCS#11 field it is compared with holds: it can match nothing.");
        }
        try
        {
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new UriFormatException($"the value of '{name}' does not decode to UTF-8.");
        }
    }

    private static void ThrowIfNotTaken(string name)
    {
        if (Taken.Contains(name))
            return;
        throw new UriFormatException($"the attribute '{name}' is not one this library takes (token, manufacturer, serial, " +
            "model, slot-description, slot-manufacturer, slot-id, library-description, library-manufacturer, " +
            "library-version, object, type, id). It is refused rather than ignored, which could select something else.");
    }

    private static void ThrowForQuery(string query)
    {
        // Only the names are looked at: a pin-value must not reach a message.
        foreach (string name in query.Split('&').Select(attribute => attribute.Split('=', 2)[0]))
        {
            if (name is "pin-value" or "pin-source")
            {
                throw new UriFormatException($"it carries '{name}': the library never takes a PIN from a URI. Read the PIN " +
                    "from a secret store and pass it to Pkcs11Slot.Login.");
            }
            if (name is "module-name" or "module-path")
            {
                throw new UriFormatException($"it carries '{name}': the library never loads a module from a URI. The module " +
                    "is the one Pkcs11Library.Load loaded.");
            }
        }
        throw new UriFormatException("it has query attributes (after '?'), which this library does not take. Remove them.");
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

    private static ulong ParseSlotId(string value)
    {
        if (value.Length == 0 || !value.All(char.IsAsciiDigit)
            || !ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong id))
        {
            throw new UriFormatException("'slot-id' must be a decimal number.");
        }
        return id;
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
