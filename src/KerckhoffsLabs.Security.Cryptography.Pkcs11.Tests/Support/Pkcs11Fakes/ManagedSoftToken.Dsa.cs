using System.Numerics;
using System.Security.Cryptography;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Pkcs11Fakes;

// DSA: the BCL can't generate a key inside a caller-provided (P,Q,G) domain, so DSA keys are
// IMPORTED via C_CreateObject. We reconstruct a live BCL DSA from the imported attributes; the
// private object carries x (CKA_VALUE) but not y, so we recompute y = g^x mod p.
internal sealed partial class ManagedSoftToken
{
    private void RegisterImportedAsymKey(ulong handle, Dictionary<ulong, byte[]> attrs)
    {
        if (!attrs.TryGetValue((ulong)CKA.CKA_KEY_TYPE, out var kt) || (CKK)ToUlong(kt) != CKK.CKK_DSA)
            return;
        if (!attrs.TryGetValue((ulong)CKA.CKA_PRIME, out var p) ||
            !attrs.TryGetValue((ulong)CKA.CKA_SUBPRIME, out var q) ||
            !attrs.TryGetValue((ulong)CKA.CKA_BASE, out var g) ||
            !attrs.TryGetValue((ulong)CKA.CKA_VALUE, out var value))
            return;

        bool isPrivate = attrs.TryGetValue((ulong)CKA.CKA_CLASS, out var cls)
            && (CKO)ToUlong(cls) == CKO.CKO_PRIVATE_KEY;

        var dp = new DSAParameters { P = p, Q = q, G = g };
        if (isPrivate)
        {
            dp.X = value;                          // private value x
            dp.Y = ModPow(g, value, p, p.Length);  // y = g^x mod p, left-padded to |p|
        }
        else
        {
            dp.Y = value;                          // public value y
        }

        var dsa = DSA.Create();
        dsa.ImportParameters(dp);
        _asymKeys[handle] = dsa;
    }

    private static byte[] ModPow(byte[] baseBe, byte[] expBe, byte[] modBe, int length)
    {
        BigInteger result = BigInteger.ModPow(
            new BigInteger(baseBe, isUnsigned: true, isBigEndian: true),
            new BigInteger(expBe, isUnsigned: true, isBigEndian: true),
            new BigInteger(modBe, isUnsigned: true, isBigEndian: true));

        byte[] be = result.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (be.Length >= length) return be;

        byte[] padded = new byte[length];
        be.CopyTo(padded, length - be.Length);
        return padded;
    }
}
