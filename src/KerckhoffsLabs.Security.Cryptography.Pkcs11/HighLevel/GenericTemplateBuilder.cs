namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
/// Fluent builder for an empty <see cref="ObjectTemplate"/> with no preset attributes.
/// Use this when constructing a template for an object class not covered by the typed
/// builders (vendor-defined CKO values).
/// </summary>
public sealed class GenericTemplateBuilder : ObjectTemplateBuilderBase<GenericTemplateBuilder>
{
    internal GenericTemplateBuilder() { }
}
