namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy.Catalogue;

/// <summary>
/// Who refused a request, as refusal hints name it: the policy's name, and for a built-in the expression that
/// reaches it (<c>CryptoPolicy.Recommended</c>).
/// </summary>
/// <param name="Name">The refusing policy's <see cref="ICryptoPolicy.Name"/>.</param>
/// <param name="BuiltInReference">The built-in's expression, or <see langword="null"/> for any other policy.</param>
internal readonly record struct PolicyIdentity(string Name, string? BuiltInReference)
{
    /// <summary>
    /// How a refusal tells the caller to widen this policy with <paramref name="call"/>: a built-in through its
    /// expression, any other policy by name.
    /// </summary>
    public string WideningCall(string call) =>
        BuiltInReference is { } reference
            ? $"{reference}.ToBuilder(...).{call}"
            : $"ToBuilder(...).{call} on the {Name} policy";
}
