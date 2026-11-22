using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fixtures;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Objects;

/// <summary>
/// NSS softoken's <c>NSC_GetAttributeValue</c> copies an attribute's whole value whatever <c>ulValueLen</c> says. A
/// search that read a found key's label or id into a fixed buffer shorter than the value would have it overrun the
/// stack and crash the process; the label and the id are read at the lengths NSS reports instead.
/// </summary>
[Collection("Nss")]
public sealed class LongAttributeReadTests_Nss(NssBackendFixture backend)
{
    private readonly NssBackendFixture _backend = backend;

    [Fact(SkipUnless = nameof(NssBackendFixture.NssAvailable), SkipType = typeof(NssBackendFixture), Skip = "Requires " + nameof(NssBackendFixture.NssAvailable))]
    public void FindKeys_ReadsALongLabelAndId_WithoutOverrunningTheBuffer()
    {
        string label = $"long-label-{Guid.NewGuid():N}-{new string('L', 1000)}";
        byte[] id = Enumerable.Range(0, 300).Select(i => (byte)(i % 256)).ToArray();
        using var session = _backend.OpenSession();
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES).Label(label).Id(id).ValueLen(32).Encrypt().Build();
        using Pkcs11Key generated = session.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);

        using var filter = ObjectTemplate.Empty().Label(label).Build();
        using var found = session.FindKeys(filter);

        Pkcs11Key key = Assert.Single(found);
        Assert.Equal(label, key.Label);
        Assert.Equal(id, key.Id.ToArray());
    }
}
