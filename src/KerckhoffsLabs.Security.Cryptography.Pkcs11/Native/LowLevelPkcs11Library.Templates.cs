namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

internal sealed partial class LowLevelPkcs11Library
{
    /// <summary>
    /// Copies a unified attribute template into the Pack=1 Windows layout for the duration of a single
    /// call. Empty in, null out: a NULL template is a legitimate Cryptoki argument.
    /// </summary>
    /// <remarks>Internal so the conversion can be tested on every OS, not only where it is called.</remarks>
    internal static CK_ATTRIBUTE_Windows[]? ToWindowsTemplate(ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        if (template.IsEmpty)
            return null;

        var packed = new CK_ATTRIBUTE_Windows[template.Length];
        for (int i = 0; i < template.Length; i++)
            packed[i] = CK_ATTRIBUTE_Windows.FromUnified(in template[i]);
        return packed;
    }
}
