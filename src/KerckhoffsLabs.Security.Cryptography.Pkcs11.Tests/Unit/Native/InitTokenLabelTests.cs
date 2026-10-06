using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.FakeModules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// <c>C_InitToken</c>'s <c>pLabel</c> carries no length; the module reads 32 bytes from it. The wrapper
/// that pins the label refuses any other length before the module is called, so a short label can
/// never become a read past the pinned buffer.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class InitTokenLabelTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void LabelNot32Bytes_IsRefused_BeforeTheModuleIsCalled(int length)
    {
        using var module = new InitTokenModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();

        var e = Assert.Throws<ArgumentOutOfRangeException>(() =>
            lowLevel.C_InitToken((NativeCULong)0UL, default, new byte[length]));

        Assert.Equal("label", e.ParamName);
        Assert.Equal(0, module.CallCount("C_InitToken"));
    }

    [Fact]
    public void Label32Bytes_ReachesTheModule()
    {
        using var module = new InitTokenModule();
        using LowLevelPkcs11Library lowLevel = module.LoadLowLevel();
        byte[] label = new byte[32];
        Array.Fill(label, (byte)' ');
        "fresh"u8.CopyTo(label);

        CKR rv = lowLevel.C_InitToken((NativeCULong)0UL, default, label);

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.Equal(label, module.Label);
    }

    private sealed class InitTokenModule : FakeModule
    {
        public byte[]? Label { get; private set; }

        protected override CKR C_InitToken(NativeCULong slotId, ReadOnlySpan<byte> pin, ReadOnlySpan<byte> label)
        {
            Label = label.ToArray();
            return CKR.CKR_OK;
        }
    }
}
