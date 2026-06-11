using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Objects;

/// <summary>
/// Covers the shared <c>ObjectTemplateBuilderBase</c> convenience setters (<c>Label</c>, <c>Id</c>,
/// <c>OnToken</c>) that the per-type builder tests don't exercise.
/// </summary>
public sealed class ObjectTemplateBuilderHelpersTests
{
    [Fact]
    public void Label_Id_OnToken_AddOneAttributeEach()
    {
        using var template = ObjectTemplate.Empty()
            .Label("my-key")
            .Id(new byte[] { 0x01, 0x02 })
            .OnToken()
            .Build();

        Assert.Equal(3, template.Count);
    }

    [Fact]
    public void OnToken_False_SetsSessionObject()
    {
        using var template = ObjectTemplate.Empty()
            .OnToken(false)
            .Build();

        Assert.Equal(1, template.Count);
    }
}
