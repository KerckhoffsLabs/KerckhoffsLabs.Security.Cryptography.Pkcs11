namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>Allows every request. Use only for legacy interop, ideally through a scoped <c>UsePolicy</c> lease.</summary>
internal sealed class AllowInsecurePolicy : ICryptoPolicy
{
    public string Name => "AllowInsecure";
    public bool AllowsOverride => true;

    public PolicyDecision Evaluate(PolicyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return PolicyDecision.Allow;
    }
}
