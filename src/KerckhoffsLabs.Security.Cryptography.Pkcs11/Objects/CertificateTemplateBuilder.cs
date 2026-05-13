using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

/// <summary>
/// Fluent builder for a certificate template (CKO_CERTIFICATE).
/// </summary>
public sealed class CertificateTemplateBuilder : ObjectTemplateBuilderBase<CertificateTemplateBuilder>
{
    internal CertificateTemplateBuilder(CKC certType)
    {
        Set(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
        Set(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, certType));
    }

    /// <summary>Sets <c>CKA_SUBJECT</c> — DER-encoded subject name.</summary>
    public CertificateTemplateBuilder Subject(ReadOnlySpan<byte> subject)
        => Attribute(CKA.CKA_SUBJECT, subject);

    /// <summary>Sets <c>CKA_VALUE</c> — DER-encoded certificate body.</summary>
    public CertificateTemplateBuilder Value(ReadOnlySpan<byte> certificate)
        => Attribute(CKA.CKA_VALUE, certificate);

    /// <summary>Sets <c>CKA_TRUSTED</c>.</summary>
    public CertificateTemplateBuilder Trusted(bool value = true)
        => Attribute(CKA.CKA_TRUSTED, value);

    /// <summary>Sets <c>CKA_ISSUER</c> — DER-encoded issuer name.</summary>
    public CertificateTemplateBuilder Issuer(ReadOnlySpan<byte> issuer)
        => Attribute(CKA.CKA_ISSUER, issuer);

    /// <summary>Sets <c>CKA_SERIAL_NUMBER</c> — DER-encoded serial number.</summary>
    public CertificateTemplateBuilder SerialNumber(ReadOnlySpan<byte> serial)
        => Attribute(CKA.CKA_SERIAL_NUMBER, serial);
}
