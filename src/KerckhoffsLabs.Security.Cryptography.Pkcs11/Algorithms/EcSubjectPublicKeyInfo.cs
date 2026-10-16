using System.Formats.Asn1;
using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// Turns the RFC 5480 <c>SubjectPublicKeyInfo</c> that <see cref="Pkcs11Key.Export"/> writes for an EC
/// key into the <see cref="ECParameters"/> the BCL's <c>ExportParameters(false)</c> returns.
/// </summary>
/// <remarks>
/// Parsed here rather than through <c>ECDiffieHellman.ImportSubjectPublicKeyInfo</c>: that needs the
/// platform to implement the curve, and <c>ExportParameters</c> has to work for any named curve the
/// token holds.
/// </remarks>
internal static class EcSubjectPublicKeyInfo
{
    internal static ECParameters ToECParameters(Pkcs11Key key)
    {
        byte[] spki = key.Export(Pkcs11KeyBlobFormat.SubjectPublicKeyInfo);
        try
        {
            var outer = new AsnReader(spki, AsnEncodingRules.DER);
            AsnReader info = outer.ReadSequence();
            AsnReader algorithm = info.ReadSequence();
            algorithm.ReadObjectIdentifier();
            string curveOid = algorithm.ReadObjectIdentifier();
            byte[] point = info.ReadBitString(out _);

            int coordinateLength = (point.Length - 1) / 2;
            return new ECParameters
            {
                Curve = ECCurve.CreateFromValue(curveOid),
                Q = new ECPoint { X = point[1..(1 + coordinateLength)], Y = point[(1 + coordinateLength)..] },
            };
        }
        catch (AsnContentException ex)
        {
            // Pkcs11Key.Export writes this encoding itself, so reaching here is a library bug.
            throw new CryptographicException("Pkcs11Key.Export returned a malformed EC SubjectPublicKeyInfo.", ex);
        }
    }
}
