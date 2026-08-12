namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;

/// <summary>The cryptoki version that introduced a function. Determines where its pointer is bound.</summary>
internal enum Cryptoki
{
    /// <summary>Bound from <c>CK_FUNCTION_LIST</c> in <c>Initialize</c>.</summary>
    V240,
    /// <summary>Bound from <c>CK_FUNCTION_LIST_3_0</c>, or by symbol lookup as a fallback.</summary>
    V300,
    /// <summary>Bound from <c>CK_FUNCTION_LIST_3_2</c>, or by symbol lookup as a fallback.</summary>
    V320,
}

/// <summary>
/// Marks a <see cref="Delegates"/> method as a cryptoki entry point. The generator derives the
/// native signature from the managed one and emits the function-pointer field, the binding, and —
/// when the method is <c>partial</c> — the body.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false, Inherited = false)]
internal sealed class Pkcs11FunctionAttribute(Cryptoki version) : Attribute
{
    /// <summary>The version that introduced this function.</summary>
    public Cryptoki Version { get; } = version;

    /// <summary>
    /// True when a parameter embeds a <c>NativeCULong</c>-sensitive struct, so the module needs a
    /// Pack=1 twin bound from the same address and a conversion on the Windows path.
    /// </summary>
    public bool WindowsLayout { get; init; }
}

/// <summary>
/// Marks a <c>ReadOnlySpan&lt;byte&gt;</c> parameter the native call takes without a length —
/// a fixed-width field or a NUL-terminated string.
/// </summary>
[AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
internal sealed class UnsizedAttribute : Attribute;

/// <summary>
/// Marks a <c>ref</c> struct parameter the token fills rather than reads. On the Windows path the
/// packed struct is converted back with <c>ToUnified()</c> after the call instead of being
/// converted with <c>FromUnified()</c> before it.
/// </summary>
[AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
internal sealed class FilledByTokenAttribute : Attribute;
