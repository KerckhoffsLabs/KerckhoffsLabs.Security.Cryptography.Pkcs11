using KerckhoffsLabs.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Native;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Support.Fakes.Modules;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Tests.Unit.Native;

/// <summary>
/// <see cref="UlongAttributeReader"/> against a module that writes the template as each test says. A value
/// counts only when the module wrote exactly one <c>CK_ULONG</c> and it is not <c>CK_UNAVAILABLE_INFORMATION</c>;
/// a return code outside the four that still answer per attribute leaves every value unreported.
/// </summary>
[Collection(FakeModuleCollection.Name)]
public sealed class UlongAttributeReaderTests
{
    private static readonly CKA[] Types = [CKA.CKA_CLASS, CKA.CKA_KEY_TYPE, CKA.CKA_MODULUS_BITS];

    public static TheoryData<int, int> MismatchedSlots => new()
    {
        { 3, 2 },                                           // fewer value slots than types
        { 0, 0 },                                           // nothing asked for
        { UlongAttributeReader.MaxAttributes + 1, UlongAttributeReader.MaxAttributes + 1 },
    };

    [Theory]
    [MemberData(nameof(MismatchedSlots))]
    public void Read_RefusesAnAttributeCountItCannotServe(int typeCount, int valueCount)
    {
        using var module = new TemplateAnswerModule((_, _) => CKR.CKR_OK);
        CKA[] types = [.. Enumerable.Repeat(CKA.CKA_CLASS, typeCount)];

        var ex = module.With(library => Record.Exception(() =>
            UlongAttributeReader.Read(library, (NativeCULong)1UL, (NativeCULong)1UL, types, new ulong?[valueCount])));

        Assert.Equal("types", Assert.IsType<ArgumentException>(ex).ParamName);
        Assert.False(module.Calls.ContainsKey("C_GetAttributeValue"));
    }

    [Fact]
    public void Read_ValuesWrittenAtOneCkUlong_AreReported()
    {
        (CKR rv, ulong?[] values) = Read((_, template) =>
        {
            for (int i = 0; i < template.Length; i++)
                Attributes.Ulong(ref template[i], 10 + (ulong)i);
            return CKR.CKR_OK;
        });

        Assert.Equal(CKR.CKR_OK, rv);
        Assert.Equal([10UL, 11UL, 12UL], values);
    }

    // CKR_ATTRIBUTE_SENSITIVE (like the other per-attribute codes) still answers the attributes the module did
    // write; the one marked CK_UNAVAILABLE_INFORMATION, and one written at another length, are not reported.
    [Fact]
    public void Read_PerAttributeCode_ReportsOnlyTheEntriesWrittenAtOneCkUlong()
    {
        (CKR rv, ulong?[] values) = Read((_, template) =>
        {
            Attributes.Ulong(ref template[0], 7);
            Attributes.Unavailable(ref template[1]);
            Attributes.Ulong(ref template[2], 9);
            template[2].valueLen = (NativeCULong)1UL;
            return CKR.CKR_ATTRIBUTE_SENSITIVE;
        });

        Assert.Equal(CKR.CKR_ATTRIBUTE_SENSITIVE, rv);
        Assert.Equal([7UL, null, null], values);
    }

    // A module that writes the values and then fails the call: nothing it wrote is trusted, and its code goes back.
    [Fact]
    public void Read_OtherReturnCode_ReportsNothing_AndReturnsTheCode()
    {
        (CKR rv, ulong?[] values) = Read((_, template) =>
        {
            for (int i = 0; i < template.Length; i++)
                Attributes.Ulong(ref template[i], 5);
            return CKR.CKR_DEVICE_ERROR;
        });

        Assert.Equal(CKR.CKR_DEVICE_ERROR, rv);
        Assert.All(values, Assert.Null);
    }

    // An entry the module leaves untouched keeps its buffer's CK_UNAVAILABLE_INFORMATION: not reported, never 0.
    [Fact]
    public void Read_EntryTheModuleLeavesUntouched_IsNotReported()
    {
        (_, ulong?[] values) = Read((_, template) =>
        {
            Attributes.Ulong(ref template[0], 3);
            return CKR.CKR_OK;
        });

        Assert.Equal([3UL, null, null], values);
    }

    private static (CKR Rv, ulong?[] Values) Read(TemplateAnswer answer)
    {
        using var module = new TemplateAnswerModule(answer);
        ulong?[] values = new ulong?[Types.Length];
        CKR rv = module.With(library => UlongAttributeReader.Read(library, (NativeCULong)1UL, (NativeCULong)1UL, Types, values));
        return (rv, values);
    }
}
