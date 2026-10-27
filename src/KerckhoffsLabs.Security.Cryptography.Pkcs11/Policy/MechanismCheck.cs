using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// A reusable check on a mechanism's parameters, attached to an allow-list entry with
/// <see cref="CryptoPolicyBuilder.AllowMechanism(CKM, IEnumerable{CryptoOperation}, string, MechanismCheck?)"/>. It runs once the mechanism is allowed for the
/// requested operation, and its denial is the policy's answer. Create one with <see cref="MechanismChecks"/>.
/// </summary>
/// <remarks>
/// Immutable, so one instance may be shared by several entries and policies. Two checks are equal when they make
/// the same decisions — the same kind of check with the same sets or floor — whatever their denial wording.
/// </remarks>
public abstract class MechanismCheck
{
    private protected MechanismCheck(string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(description);
        Description = description;
    }

    /// <summary>What the check requires, as a lowercase phrase (for example "tag of at least 96 bits").</summary>
    public string Description { get; }

    /// <summary>Decides the request; <paramref name="owner"/> is the catalogue of the policy evaluating it.</summary>
    internal abstract PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner);

    /// <summary>What the check decides from, for value equality: equal keys make the same decisions.</summary>
    private protected abstract object DecisionKey { get; }

    /// <inheritdoc/>
    public sealed override bool Equals(object? obj) =>
        obj is MechanismCheck other && other.GetType() == GetType() && Equals(DecisionKey, other.DecisionKey);

    /// <inheritdoc/>
    public sealed override int GetHashCode() => HashCode.Combine(GetType(), DecisionKey);

    /// <inheritdoc/>
    public override string ToString() => Description;

    /// <summary>A stable, order-independent key for a set of values.</summary>
    private protected static string SetKey<T>(IEnumerable<T> values) =>
        string.Join(",", values.Select(v => v!.ToString()).Order(StringComparer.Ordinal));

    /// <summary>A check backed by a delegate. Test seam: production policies use the <see cref="MechanismChecks"/> checks.</summary>
    internal static MechanismCheck FromDelegate(Func<Mechanism, CryptoOperation, PolicyDecision> check, string description)
        => new DelegateCheck(check, description);

    private sealed class DelegateCheck(Func<Mechanism, CryptoOperation, PolicyDecision> check, string description)
        : MechanismCheck(description)
    {
        private protected override object DecisionKey => check;

        internal override PolicyDecision Evaluate(Mechanism mechanism, CryptoOperation operation, PolicyCatalogue owner)
            => check(mechanism, operation);
    }
}
