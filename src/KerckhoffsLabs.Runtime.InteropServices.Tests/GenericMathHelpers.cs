// Licensed under the MIT License
// Adapted from dotnet/runtime for NativeCULong testing

using System.Numerics;

namespace KerckhoffsLabs.Runtime.InteropServices.Tests;

public static class AdditionOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IAdditionOperators<TSelf, TOther, TResult>
{
    public static TResult op_Addition(TSelf left, TOther right) => unchecked(left + right);
    public static TResult op_CheckedAddition(TSelf left, TOther right) => checked(left + right);
}

public static class AdditiveIdentityHelper<TSelf, TResult>
    where TSelf : IAdditiveIdentity<TSelf, TResult>
{
    public static TResult AdditiveIdentity => TSelf.AdditiveIdentity;
}

public static class BinaryIntegerHelper<TSelf>
    where TSelf : IBinaryInteger<TSelf>
{
    public static (TSelf Quotient, TSelf Remainder) DivRem(TSelf left, TSelf right) => TSelf.DivRem(left, right);
    public static TSelf LeadingZeroCount(TSelf value) => TSelf.LeadingZeroCount(value);
    public static TSelf PopCount(TSelf value) => TSelf.PopCount(value);
    public static TSelf RotateLeft(TSelf value, int rotateAmount) => TSelf.RotateLeft(value, rotateAmount);
    public static TSelf RotateRight(TSelf value, int rotateAmount) => TSelf.RotateRight(value, rotateAmount);
    public static TSelf TrailingZeroCount(TSelf value) => TSelf.TrailingZeroCount(value);
    public static int GetByteCount(TSelf value) => value.GetByteCount();
    public static int GetShortestBitLength(TSelf value) => value.GetShortestBitLength();
    public static bool TryReadBigEndian(ReadOnlySpan<byte> source, bool isUnsigned, out TSelf value)
        => TSelf.TryReadBigEndian(source, isUnsigned, out value);
    public static bool TryReadLittleEndian(ReadOnlySpan<byte> source, bool isUnsigned, out TSelf value)
        => TSelf.TryReadLittleEndian(source, isUnsigned, out value);
    public static bool TryWriteBigEndian(TSelf value, Span<byte> destination, out int bytesWritten)
        => value.TryWriteBigEndian(destination, out bytesWritten);
    public static bool TryWriteLittleEndian(TSelf value, Span<byte> destination, out int bytesWritten)
        => value.TryWriteLittleEndian(destination, out bytesWritten);
}

public static class BinaryNumberHelper<TSelf>
    where TSelf : IBinaryNumber<TSelf>
{
    public static bool IsPow2(TSelf value) => TSelf.IsPow2(value);
    public static TSelf Log2(TSelf value) => TSelf.Log2(value);
}

public static class BitwiseOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IBitwiseOperators<TSelf, TOther, TResult>
{
    public static TResult op_BitwiseAnd(TSelf left, TOther right) => left & right;
    public static TResult op_BitwiseOr(TSelf left, TOther right) => left | right;
    public static TResult op_ExclusiveOr(TSelf left, TOther right) => left ^ right;
    public static TResult op_OnesComplement(TSelf value) => ~value;
}

public static class ComparisonOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IComparisonOperators<TSelf, TOther, TResult>
{
    public static TResult op_GreaterThan(TSelf left, TOther right) => left > right;
    public static TResult op_GreaterThanOrEqual(TSelf left, TOther right) => left >= right;
    public static TResult op_LessThan(TSelf left, TOther right) => left < right;
    public static TResult op_LessThanOrEqual(TSelf left, TOther right) => left <= right;
}

public static class DecrementOperatorsHelper<TSelf>
    where TSelf : IDecrementOperators<TSelf>
{
    public static TSelf op_Decrement(TSelf value) => unchecked(--value);
    public static TSelf op_CheckedDecrement(TSelf value) => checked(--value);
}

public static class DivisionOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IDivisionOperators<TSelf, TOther, TResult>
{
    public static TResult op_Division(TSelf left, TOther right) => left / right;
    public static TResult op_CheckedDivision(TSelf left, TOther right) => checked(left / right);
}

public static class EqualityOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IEqualityOperators<TSelf, TOther, TResult>
{
    public static TResult op_Equality(TSelf left, TOther right) => left == right;
    public static TResult op_Inequality(TSelf left, TOther right) => left != right;
}

public static class IncrementOperatorsHelper<TSelf>
    where TSelf : IIncrementOperators<TSelf>
{
    public static TSelf op_Increment(TSelf value) => unchecked(++value);
    public static TSelf op_CheckedIncrement(TSelf value) => checked(++value);
}

public static class ModulusOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IModulusOperators<TSelf, TOther, TResult>
{
    public static TResult op_Modulus(TSelf left, TOther right) => left % right;
}

public static class MultiplicativeIdentityHelper<TSelf, TResult>
    where TSelf : IMultiplicativeIdentity<TSelf, TResult>
{
    public static TResult MultiplicativeIdentity => TSelf.MultiplicativeIdentity;
}

public static class MultiplyOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IMultiplyOperators<TSelf, TOther, TResult>
{
    public static TResult op_Multiply(TSelf left, TOther right) => unchecked(left * right);
    public static TResult op_CheckedMultiply(TSelf left, TOther right) => checked(left * right);
}

public static class NumberHelper<TSelf>
    where TSelf : INumber<TSelf>
{
    public static TSelf Abs(TSelf value) => TSelf.Abs(value);
    public static TSelf Clamp(TSelf value, TSelf min, TSelf max) => TSelf.Clamp(value, min, max);
    public static TSelf CopySign(TSelf value, TSelf sign) => TSelf.CopySign(value, sign);
    public static TSelf Max(TSelf x, TSelf y) => TSelf.Max(x, y);
    public static TSelf MaxMagnitude(TSelf x, TSelf y) => TSelf.MaxMagnitude(x, y);
    public static TSelf Min(TSelf x, TSelf y) => TSelf.Min(x, y);
    public static TSelf MinMagnitude(TSelf x, TSelf y) => TSelf.MinMagnitude(x, y);
    public static int Sign(TSelf value) => TSelf.Sign(value);
}

public static class NumberBaseHelper<TSelf>
    where TSelf : INumberBase<TSelf>
{
    public static TSelf One => TSelf.One;
    public static TSelf Zero => TSelf.Zero;
    public static int Radix => TSelf.Radix;

    public static bool IsCanonical(TSelf value) => TSelf.IsCanonical(value);
    public static bool IsComplexNumber(TSelf value) => TSelf.IsComplexNumber(value);
    public static bool IsEvenInteger(TSelf value) => TSelf.IsEvenInteger(value);
    public static bool IsFinite(TSelf value) => TSelf.IsFinite(value);
    public static bool IsImaginaryNumber(TSelf value) => TSelf.IsImaginaryNumber(value);
    public static bool IsInfinity(TSelf value) => TSelf.IsInfinity(value);
    public static bool IsInteger(TSelf value) => TSelf.IsInteger(value);
    public static bool IsNaN(TSelf value) => TSelf.IsNaN(value);
    public static bool IsNegative(TSelf value) => TSelf.IsNegative(value);
    public static bool IsNegativeInfinity(TSelf value) => TSelf.IsNegativeInfinity(value);
    public static bool IsNormal(TSelf value) => TSelf.IsNormal(value);
    public static bool IsOddInteger(TSelf value) => TSelf.IsOddInteger(value);
    public static bool IsPositive(TSelf value) => TSelf.IsPositive(value);
    public static bool IsPositiveInfinity(TSelf value) => TSelf.IsPositiveInfinity(value);
    public static bool IsRealNumber(TSelf value) => TSelf.IsRealNumber(value);
    public static bool IsSubnormal(TSelf value) => TSelf.IsSubnormal(value);
    public static bool IsZero(TSelf value) => TSelf.IsZero(value);

    public static TSelf MaxMagnitudeNumber(TSelf x, TSelf y) => TSelf.MaxMagnitudeNumber(x, y);
    public static TSelf MinMagnitudeNumber(TSelf x, TSelf y) => TSelf.MinMagnitudeNumber(x, y);

    public static TSelf CreateChecked<TOther>(TOther value) where TOther : INumberBase<TOther>
        => TSelf.CreateChecked(value);
    public static TSelf CreateSaturating<TOther>(TOther value) where TOther : INumberBase<TOther>
        => TSelf.CreateSaturating(value);
    public static TSelf CreateTruncating<TOther>(TOther value) where TOther : INumberBase<TOther>
        => TSelf.CreateTruncating(value);
}

public static class ShiftOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : IShiftOperators<TSelf, TOther, TResult>
{
    public static TResult op_LeftShift(TSelf value, TOther shiftAmount) => value << shiftAmount;
    public static TResult op_RightShift(TSelf value, TOther shiftAmount) => value >> shiftAmount;
    public static TResult op_UnsignedRightShift(TSelf value, TOther shiftAmount) => value >>> shiftAmount;
}

public static class SubtractionOperatorsHelper<TSelf, TOther, TResult>
    where TSelf : ISubtractionOperators<TSelf, TOther, TResult>
{
    public static TResult op_Subtraction(TSelf left, TOther right) => unchecked(left - right);
    public static TResult op_CheckedSubtraction(TSelf left, TOther right) => checked(left - right);
}

public static class UnaryNegationOperatorsHelper<TSelf, TResult>
    where TSelf : IUnaryNegationOperators<TSelf, TResult>
{
    public static TResult op_UnaryNegation(TSelf value) => unchecked(-value);
    public static TResult op_CheckedUnaryNegation(TSelf value) => checked(-value);
}

public static class UnaryPlusOperatorsHelper<TSelf, TResult>
    where TSelf : IUnaryPlusOperators<TSelf, TResult>
{
    public static TResult op_UnaryPlus(TSelf value) => +value;
}
