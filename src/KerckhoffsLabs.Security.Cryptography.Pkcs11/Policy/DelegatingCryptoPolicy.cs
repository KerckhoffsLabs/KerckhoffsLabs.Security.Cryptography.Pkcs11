namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Policy;

/// <summary>
/// A policy that wraps another: it forwards <see cref="Name"/>, <see cref="AllowsOverride"/> and
/// <see cref="InspectsKeys"/> to the policy it wraps, and decides each request in <see cref="Evaluate"/>, usually
/// by deciding a few itself and passing the rest on with <c>Inner.Evaluate(request)</c>.
/// </summary>
/// <remarks>
/// <para>
/// Derive a logging or extra-rule decorator from this rather than implementing <see cref="ICryptoPolicy"/> over
/// another policy by hand. <see cref="ICryptoPolicy.InspectsKeys"/> defaults to <see langword="false"/>, so a
/// hand-written wrapper that does not forward it turns off the key-size checks of the policy it wraps
/// (<see cref="CryptoPolicy.Cnsa20"/>). A wrapper that does is refused when it is installed (see
/// <see cref="Pkcs11LibraryOptions.Policy"/>), but this class gets it right from the start.
/// </para>
/// <code>
/// sealed class NoExportAfterHours(ICryptoPolicy inner, TimeProvider clock) : DelegatingCryptoPolicy(inner)
/// {
///     public override string Name => $"{Inner.Name}+NoExportAfterHours";
///
///     public override PolicyDecision Evaluate(PolicyRequest request) => request switch
///     {
///         KeyMaterialExportRequest when clock.GetLocalNow().Hour is &lt; 8 or &gt;= 18 =>
///             PolicyDecision.Deny("Reading secrets off the token is allowed during business hours only."),
///         _ => Inner.Evaluate(request),
///     };
/// }
/// </code>
/// </remarks>
public abstract class DelegatingCryptoPolicy : ICryptoPolicy
{
    /// <summary>Wraps <paramref name="inner"/>.</summary>
    /// <param name="inner">The policy this one wraps.</param>
    /// <exception cref="ArgumentNullException"><paramref name="inner"/> is <see langword="null"/>.</exception>
    protected DelegatingCryptoPolicy(ICryptoPolicy inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        Inner = inner;
    }

    /// <summary>The policy this one wraps.</summary>
    protected ICryptoPolicy Inner { get; }

    /// <inheritdoc/>
    /// <remarks>The wrapped policy's, unless overridden.</remarks>
    public virtual string Name => Inner.Name;

    /// <inheritdoc/>
    /// <remarks>The wrapped policy's, unless overridden.</remarks>
    public virtual bool AllowsOverride => Inner.AllowsOverride;

    /// <inheritdoc/>
    /// <remarks>
    /// The wrapped policy's, unless overridden: a wrapper that judges key strength itself returns
    /// <see langword="true"/>; one that returns <see langword="false"/> over a policy that inspects keys turns its
    /// key-size checks off, and is refused when it is installed.
    /// </remarks>
    public virtual bool InspectsKeys => Inner.InspectsKeys;

    /// <inheritdoc/>
    public abstract PolicyDecision Evaluate(PolicyRequest request);
}
