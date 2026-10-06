namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>
/// The Cryptoki interface versions, as a module reports them in <c>CK_INFO.cryptokiVersion</c> and
/// <c>CK_FUNCTION_LIST.version</c>: the headers' <c>CRYPTOKI_VERSION_MAJOR</c> and
/// <c>CRYPTOKI_VERSION_MINOR</c>. v2.40 is <c>{2, 40}</c>, but v3.0, v3.1 and v3.2 are <c>{3, 0}</c>,
/// <c>{3, 1}</c> and <c>{3, 2}</c>.
/// </summary>
internal static class CryptokiVersions
{
    public static readonly Version V2_40 = new(2, 40);
    public static readonly Version V3_0 = new(3, 0);
    public static readonly Version V3_1 = new(3, 1);
    public static readonly Version V3_2 = new(3, 2);
}
