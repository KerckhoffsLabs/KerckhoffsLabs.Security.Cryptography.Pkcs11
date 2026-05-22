using KerckhoffsLabs.Security.Cryptography.Pkcs11.Internal;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Internal;

public sealed class ObjectHandleTests
{
    [Fact]
    public void Constructed_ExposesObjectIdAndIsNotInvalid()
    {
        var h = new ObjectHandle(0x42UL);
        Assert.Equal(0x42UL, h.ObjectId);
        Assert.False(h.IsInvalid);
    }

    [Fact]
    public void Invalid_EqualsDefault_AndIsInvalid()
    {
        Assert.Equal(default, ObjectHandle.Invalid);
        Assert.True(ObjectHandle.Invalid.IsInvalid);
        Assert.True(default(ObjectHandle).IsInvalid);
        Assert.Equal(0UL, ObjectHandle.Invalid.ObjectId);
    }

    [Fact]
    public void ToString_RendersHandleInHex()
    {
        Assert.Equal("ObjectHandle(0x2A)", new ObjectHandle(0x2AUL).ToString());
        Assert.Equal("ObjectHandle(0x0)", ObjectHandle.Invalid.ToString());
    }

    [Fact]
    public void Record_ValueEquality()
    {
        Assert.Equal(new ObjectHandle(5UL), new ObjectHandle(5UL));
        Assert.NotEqual(new ObjectHandle(5UL), new ObjectHandle(6UL));
    }
}
