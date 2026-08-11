using System.Security.Cryptography;
using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// Asymmetric key generation: C_GenerateKeyPair for RSA and EC. Generates a live BCL key, indexes it
// under BOTH handles (Sign uses the private handle, Verify the public), and synthesizes the public
// attributes the adapters read back (CKA_MODULUS/CKA_PUBLIC_EXPONENT, CKA_EC_PARAMS/CKA_EC_POINT).
internal sealed partial class ManagedSoftToken
{
    // Live BCL key indexed by handle. Holds AsymmetricAlgorithm (RSA/ECDsa) and the PQC types
    // (MLDsa/SlhDsa/MLKem), which are not AsymmetricAlgorithm — hence object.
    private readonly Dictionary<ulong, object> _asymKeys = [];

    public override CKR C_GenerateKeyPair(NativeCULong session, ref CK_MECHANISM mechanism, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate, ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate, ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        if (!_sessions.Contains((ulong)session)) return CKR.CKR_SESSION_HANDLE_INVALID;

        var pub = ReadTemplate(publicKeyTemplate);
        var priv = ReadTemplate(privateKeyTemplate);

        switch ((CKM)(ulong)mechanism.Mechanism)
        {
            case CKM.CKM_RSA_PKCS_KEY_PAIR_GEN:
                {
                    int bits = pub.TryGetValue((ulong)CKA.CKA_MODULUS_BITS, out var mb) ? (int)ToUlong(mb) : 2048;
                    var rsa = RSA.Create(bits);
                    RSAParameters pp = rsa.ExportParameters(includePrivateParameters: false);

                    SetCommon(pub, CKO.CKO_PUBLIC_KEY, CKK.CKK_RSA);
                    SetCommon(priv, CKO.CKO_PRIVATE_KEY, CKK.CKK_RSA);
                    foreach (var d in new[] { pub, priv })
                    {
                        d[(ulong)CKA.CKA_MODULUS] = pp.Modulus!;
                        d[(ulong)CKA.CKA_PUBLIC_EXPONENT] = pp.Exponent!;
                    }
                    Finish(rsa, pub, priv, ref publicKey, ref privateKey);
                    return CKR.CKR_OK;
                }

            case CKM.CKM_EC_KEY_PAIR_GEN:
                {
                    if (!pub.TryGetValue((ulong)CKA.CKA_EC_PARAMS, out var ecParams))
                        return CKR.CKR_TEMPLATE_INCOMPLETE;
                    var ec = ECDsa.Create(CurveFromOid(ecParams));
                    ECParameters ep = ec.ExportParameters(includePrivateParameters: false);
                    byte[] ecPoint = EncodeEcPoint(ep.Q);

                    SetCommon(pub, CKO.CKO_PUBLIC_KEY, CKK.CKK_EC);
                    SetCommon(priv, CKO.CKO_PRIVATE_KEY, CKK.CKK_EC);
                    foreach (var d in new[] { pub, priv })
                    {
                        d[(ulong)CKA.CKA_EC_PARAMS] = ecParams;
                        d[(ulong)CKA.CKA_EC_POINT] = ecPoint;
                    }
                    Finish(ec, pub, priv, ref publicKey, ref privateKey);
                    return CKR.CKR_OK;
                }

            default:
                return GeneratePqcKeyPair((CKM)(ulong)mechanism.Mechanism, pub, priv, ref publicKey, ref privateKey);
        }
    }

    private void Finish(object key, Dictionary<ulong, byte[]> pub, Dictionary<ulong, byte[]> priv,
        ref NativeCULong publicKey, ref NativeCULong privateKey)
    {
        ulong pubH = Store(pub), privH = Store(priv);
        _asymKeys[pubH] = key;
        _asymKeys[privH] = key; // same instance carries the private material; Sign/Verify both work
        publicKey = (NativeCULong)pubH;
        privateKey = (NativeCULong)privH;
    }

    private static void SetCommon(Dictionary<ulong, byte[]> attrs, CKO cls, CKK keyType)
    {
        attrs[(ulong)CKA.CKA_CLASS] = UlongAttr((ulong)cls);
        attrs[(ulong)CKA.CKA_KEY_TYPE] = UlongAttr((ulong)keyType);
    }

    // CK_ULONG attribute value at the platform's word width (4 bytes on Windows, 8 on Linux-LP64),
    // little-endian — matching how the session marshals CK_ULONG attributes.
    private static byte[] UlongAttr(ulong v) => BitConverter.GetBytes(v).AsSpan(0, UnmanagedMemory.NativeULongSize).ToArray();

    // Map CKA_EC_PARAMS (DER curve OID) to a BCL ECCurve via the production Pkcs11ECCurve bridge — supports
    // whatever named curves the host BCL implements (NIST, brainpool, …), not just a hardcoded few.
    private static ECCurve CurveFromOid(byte[] ecParams) =>
        Pkcs11ECCurve.FromEcParams(ecParams).ToECCurve();

    // CKA_EC_POINT = DER OCTET STRING wrapping the uncompressed point (0x04 ‖ X ‖ Y).
    private static byte[] EncodeEcPoint(ECPoint q)
    {
        byte[] point = [0x04, .. q.X!, .. q.Y!];
        if (point.Length < 0x80) return [0x04, (byte)point.Length, .. point];
        if (point.Length < 0x100) return [0x04, 0x81, (byte)point.Length, .. point];
        return [0x04, 0x82, (byte)(point.Length >> 8), (byte)(point.Length & 0xFF), .. point];
    }
}
