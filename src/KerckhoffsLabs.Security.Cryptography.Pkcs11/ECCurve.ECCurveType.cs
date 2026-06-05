namespace KerckhoffsLabs.Security.Cryptography.Pkcs11;

public readonly partial struct ECCurve
{
    /// <summary>
    /// The category of an <see cref="ECCurve"/>. The values mirror the BCL
    /// <c>System.Security.Cryptography.ECCurve.ECCurveType</c> so the two map cleanly. This PKCS#11
    /// type only ever produces <see cref="Named"/> curves (selected by OID); the other members exist
    /// for parity with the BCL and to describe the uninitialized <c>default</c>.
    /// </summary>
    public enum ECCurveType
    {
        /// <summary>No curve is set (the uninitialized <c>default</c>).</summary>
        Implicit = 0,
        /// <summary>An explicit prime-field short-Weierstrass curve.</summary>
        PrimeShortWeierstrass = 1,
        /// <summary>An explicit prime-field twisted-Edwards curve.</summary>
        PrimeTwistedEdwards = 2,
        /// <summary>An explicit prime-field Montgomery curve.</summary>
        PrimeMontgomery = 3,
        /// <summary>An explicit characteristic-2 (binary field) curve.</summary>
        Characteristic2 = 4,
        /// <summary>A curve identified by a well-known OID — the only kind PKCS#11 selects by OID.</summary>
        Named = 5,
    }
}
