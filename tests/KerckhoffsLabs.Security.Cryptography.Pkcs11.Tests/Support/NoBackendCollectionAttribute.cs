namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests;

/// <summary>
/// Marks a test class under <c>Integration/</c> that deliberately joins no backend
/// <c>[Collection]</c> — because it touches no process-global native module and is safe to run
/// concurrently with every backend collection.
/// </summary>
/// <remarks>
/// This exists so the omission of a <c>[Collection]</c> is always a decision rather than an
/// oversight: <c>TestCollectionConventionTests</c> requires one attribute or the other, and this
/// one carries a written reason. Applying it to a class that does open a shared module reintroduces
/// exactly the race the collections prevent, so the reason must be true, not merely present.
/// </remarks>
/// <param name="reason">Why this class needs no backend collection. Must be non-empty.</param>
[AttributeUsage(AttributeTargets.Class, Inherited = false)]
public sealed class NoBackendCollectionAttribute(string reason) : Attribute
{
    /// <summary>Why this class is safe to run outside every backend collection.</summary>
    public string Reason { get; } = reason;
}
