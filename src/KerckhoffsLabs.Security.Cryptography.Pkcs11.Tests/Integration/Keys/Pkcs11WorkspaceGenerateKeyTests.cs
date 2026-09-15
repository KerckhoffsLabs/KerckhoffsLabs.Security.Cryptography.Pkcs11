using System.Text;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Objects;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Integration.Keys;

/// <summary>
/// Backend-agnostic assertions for <c>Pkcs11Workspace.GenerateKey</c> (symmetric and asymmetric).
/// The per-backend test classes live in <c>Pkcs11WorkspaceGenerateKeyTests.SoftHsm2.cs</c>,
/// <c>.Nss.cs</c>, <c>.OpenCryptoki.cs</c>, and <c>.Kryoptic.cs</c>.
/// </summary>
internal static class WorkspaceGenerateKeyTestCases
{
    public static void Assert_GenerateKey_Symmetric_ReturnsKeyWithLabelAndType(Pkcs11Workspace workspace)
    {
        string label = $"gen-{Guid.NewGuid():N}";
        using var template = ObjectTemplate.ForSecretKey(CKK.CKK_AES)
            .Label(label).ValueLen(32).Encrypt().Decrypt().OnToken().Build();

        using var key = workspace.GenerateKey(new Mechanism(CKM.CKM_AES_KEY_GEN), template);

        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_AES, key.KeyType);
            Assert.False(key.PrivateHandle.IsInvalid);
        }
        finally
        {
            workspace.Session.DestroyObject(key.PrivateHandle);
        }
    }

    public static void Assert_GenerateKey_Asymmetric_ReturnsKeyWithBothHandles(Pkcs11Workspace workspace)
    {
        string label = $"gen-pair-{Guid.NewGuid():N}";
        byte[] id = Encoding.ASCII.GetBytes(label);

        using var pubTpl = ObjectTemplate.ForPublicKey(CKK.CKK_RSA)
            .Label(label).Id(id).Verify().ModulusBits(2048)
            .PublicExponent([0x01, 0x00, 0x01]).Build();
        using var privTpl = ObjectTemplate.ForPrivateKey(CKK.CKK_RSA)
            .Label(label).Id(id).Sign().Build();

        using var key = workspace.GenerateKey(
            new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
            privTpl,
            pubTpl);

        try
        {
            Assert.Equal(label, key.Label);
            Assert.Equal(CKK.CKK_RSA, key.KeyType);
            Assert.False(key.PrivateHandle.IsInvalid);
            Assert.False(key.PublicHandle.IsInvalid);
        }
        finally
        {
            workspace.Session.DestroyObject(key.PrivateHandle);
            workspace.Session.DestroyObject(key.PublicHandle);
        }
    }
}
