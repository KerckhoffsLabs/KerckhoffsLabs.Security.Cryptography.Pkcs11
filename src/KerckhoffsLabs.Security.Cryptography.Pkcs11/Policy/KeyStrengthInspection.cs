using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// Refuses, when it is installed, a policy that judges key strength but does not inspect keys: a session sends a
/// <see cref="KeyStrengthRequest"/> only to a policy whose <see cref="ICryptoPolicy.InspectsKeys"/> is
/// <see langword="true"/>, so the key-size rules of such a policy would never run. The usual cause is a wrapper
/// around <see cref="CryptoPolicy.Cnsa20"/> that does not forward <see cref="ICryptoPolicy.InspectsKeys"/>.
/// </summary>
internal static class KeyStrengthInspection
{
    // Keys of the sizes the built-ins tell apart, weak and strong for each type that has a size. A policy that
    // decides them all alike (allows every request it does not know, or denies it) does not judge key strength.
    private static readonly KeyStrengthRequest[] Probes =
    [
        new(CKK.CKK_AES, KeyStrengthSource.ExistingKey) { ValueLengthBytes = 16 },
        new(CKK.CKK_AES, KeyStrengthSource.ExistingKey) { ValueLengthBytes = 32 },
        new(CKK.CKK_ML_KEM, KeyStrengthSource.ExistingKey) { ParameterSet = (ulong)CkpMlKem.CKP_ML_KEM_512 },
        new(CKK.CKK_ML_KEM, KeyStrengthSource.ExistingKey) { ParameterSet = (ulong)CkpMlKem.CKP_ML_KEM_1024 },
        new(CKK.CKK_ML_DSA, KeyStrengthSource.ExistingKey) { ParameterSet = (ulong)CkpMlDsa.CKP_ML_DSA_44 },
        new(CKK.CKK_ML_DSA, KeyStrengthSource.ExistingKey) { ParameterSet = (ulong)CkpMlDsa.CKP_ML_DSA_87 },
        new(CKK.CKK_HSS, KeyStrengthSource.ExistingKey) { HssLevels = 1 },
        new(CKK.CKK_HSS, KeyStrengthSource.ExistingKey) { HssLevels = 2 },
    ];

    /// <summary>
    /// Throws when <paramref name="policy"/> does not inspect keys yet decides <see cref="KeyStrengthRequest"/>s
    /// differently by key size. The probes are built in memory: no token is asked. The built-in policies are
    /// consistent by construction and are not probed.
    /// </summary>
    /// <remarks>
    /// A policy that throws on a probe (one that rejects request kinds it does not know by throwing) is taken as not
    /// judging key strength: the session never sends it one, so it was working before this check.
    /// </remarks>
    /// <exception cref="ArgumentException">The policy judges key strength but does not inspect keys.</exception>
    internal static void ThrowIfJudgedWithoutInspecting(ICryptoPolicy policy, string paramName)
    {
        if (policy.InspectsKeys || policy is ComposedCryptoPolicy or AllowInsecurePolicy)
            return;

        bool? first = null;
        foreach (KeyStrengthRequest probe in Probes)
        {
            if (Allows(policy, probe) is not { } allowed)
                return;
            first ??= allowed;
            if (allowed != first)
            {
                throw new ArgumentException(
                    $"The {policy.Name} policy judges key strength (it decides key-strength requests differently by key " +
                    $"size), but its {nameof(ICryptoPolicy.InspectsKeys)} is false, so no session would ask it and its " +
                    $"key-size rules would never run. Forward {nameof(ICryptoPolicy.InspectsKeys)} from the policy it " +
                    $"wraps, or derive it from {nameof(DelegatingCryptoPolicy)}.",
                    paramName);
            }
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S2221:\"Exception\" should not be caught",
        Justification = "A caller-supplied policy may reject a request kind it does not know by throwing anything; that " +
        "only means it does not judge key strength, which is all this asks.")]
    private static bool? Allows(ICryptoPolicy policy, KeyStrengthRequest probe)
    {
        try
        {
            return policy.Evaluate(probe).IsAllowed;
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or StackOverflowException))
        {
            return null;
        }
    }
}
