namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>
/// Documents why an item (mechanism, hash, curve, or KDF) that is <em>not</em> on a restrictive
/// policy's allow-list was considered and rejected, rather than simply never reviewed.
/// </summary>
/// <remarks>
/// Documentation only: an entry here never changes a verdict. The evaluator consults this table solely
/// to choose the wording of a denial that the allow-list check has already produced, and the generated
/// catalogue documentation walks it to render each policy's deny list.
/// </remarks>
/// <param name="Reason">Why the item is refused, ideally citing a source, as one or more full sentences ending with a period. Must not contain secret material.</param>
/// <param name="Alternative">What to use instead; <see langword="null"/> when there is none.</param>
internal sealed record DocumentedRefusal(string Reason, string? Alternative);
