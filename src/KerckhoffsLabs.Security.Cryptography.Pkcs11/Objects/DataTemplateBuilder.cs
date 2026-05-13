using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Fluent builder for a data-object template (CKO_DATA).
/// </summary>
public sealed class DataTemplateBuilder : ObjectTemplateBuilderBase<DataTemplateBuilder>
{
    internal DataTemplateBuilder()
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA));
    }

    /// <summary>Sets <c>CKA_APPLICATION</c>.</summary>
    public DataTemplateBuilder Application(string application)
        => Attribute(CKA.CKA_APPLICATION, application);

    /// <summary>Sets <c>CKA_OBJECT_ID</c> — DER-encoded OID identifying the data type.</summary>
    public DataTemplateBuilder ObjectId(ReadOnlySpan<byte> derOid)
        => Attribute(CKA.CKA_OBJECT_ID, derOid);

    /// <summary>Sets <c>CKA_VALUE</c> — the data payload.</summary>
    public DataTemplateBuilder Value(ReadOnlySpan<byte> payload)
        => Attribute(CKA.CKA_VALUE, payload);
}
