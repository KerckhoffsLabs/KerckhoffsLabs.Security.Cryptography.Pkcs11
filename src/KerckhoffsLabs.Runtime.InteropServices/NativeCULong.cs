// Licensed under the MIT License

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

#if WINDOWS
using NativeType = System.UInt32;
#else
using NativeType = System.UIntPtr;
#endif

namespace KerckhoffsLabs.Runtime.InteropServices;

/// <summary>
/// <see cref="NativeCULong"/> is an immutable value type that represents the <c>unsigned long</c> type in C and C++.
/// It is meant to be used as an exchange type at the managed/unmanaged boundary to accurately represent
/// in managed code unmanaged APIs that use the <c>unsigned long</c> type.
/// This type has 32-bits of storage on all Windows platforms and 32-bit Unix-based platforms.
/// It has 64-bits of storage on 64-bit Unix platforms.
/// </summary>
[CLSCompliant(false)]
[Intrinsic]
public readonly struct NativeCULong 
    : IEquatable<NativeCULong>,
      IComparable,
      IComparable<NativeCULong>,
      ISpanFormattable,
      ISerializable,
      IBinaryInteger<NativeCULong>,
      IMinMaxValue<NativeCULong>,
      IUnsignedNumber<NativeCULong>,
      IUtf8SpanFormattable
{
    private readonly NativeType _value;

    /// <summary>
    /// Constructs an instance from a 32-bit unsigned integer.
    /// </summary>
    /// <param name="value">The integer value.</param>
    public NativeCULong(uint value)
    {
        _value = value;
    }

    /// <summary>
    /// Constructs an instance from a native-sized unsigned integer.
    /// </summary>
    /// <param name="value">The integer value.</param>
    /// <exception cref="OverflowException"><paramref name="value"/> is outside the range of the underlying storage type.</exception>
    public NativeCULong(nuint value)
    {
        _value = checked(value);
    }

    /// <summary>
    /// The underlying integer value of this instance.
    /// </summary>
    public nuint Value => _value;

    /// <summary>
    /// Returns a value indicating whether this instance is equal to a specified object.
    /// </summary>
    /// <param name="o">An object to compare with this instance.</param>
    /// <returns><c>true</c> if <paramref name="o"/> is an instance of <see cref="NativeCULong"/> and equals the value of this instance; otherwise, <c>false</c>.</returns>
    public override bool Equals([NotNullWhen(true)] object? o) => o is NativeCULong other && Equals(other);

    /// <summary>
    /// Returns a value indicating whether this instance is equal to a specified <see cref="CLong"/> value.
    /// </summary>
    /// <param name="other">A <see cref="NativeCULong"/> value to compare to this instance.</param>
    /// <returns><c>true</c> if <paramref name="other"/> has the same value as this instance; otherwise, <c>false</c>.</returns>
    public bool Equals(NativeCULong other) => _value == other._value;

    /// <summary>
    /// Returns the hash code for this instance.
    /// </summary>
    /// <returns>A 32-bit signed integer hash code.</returns>
    public override int GetHashCode() => _value.GetHashCode();

    /// <summary>
    /// Converts the numeric value of this instance to its equivalent string representation.
    /// </summary>
    /// <returns>The string representation of the value of this instance, consisting of a sequence of digits ranging from 0 to 9 with no leading zeroes.</returns>
    public override string ToString() => _value.ToString();

    /// <summary>Converts the numeric value of this instance to its equivalent string representation using the specified format.</summary>
    /// <param name="format">A numeric format string.</param>
    /// <returns>The string representation of the value of this instance as specified by <paramref name="format" />.</returns>
    /// <exception cref="FormatException"><paramref name="format" /> is invalid.</exception>
    public string ToString([StringSyntax(StringSyntaxAttribute.NumericFormat)] string? format) => _value.ToString(format);

    /// <summary>Converts the numeric value of this instance to its equivalent string representation using the specified culture-specific format information.</summary>
    /// <param name="provider">An object that supplies culture-specific formatting information.</param>
    /// <returns>The string representation of the value of this instance as specified by <paramref name="provider" />.</returns>
    public string ToString(IFormatProvider? provider) => _value.ToString(provider);

    //
    // IAdditionOperators
    //

    /// <inheritdoc cref="IAdditionOperators{TSelf, TOther, TResult}.op_Addition(TSelf, TOther)" />
    public static NativeCULong operator +(NativeCULong left, NativeCULong right) => new(left._value + right._value);

    /// <inheritdoc cref="IAdditionOperators{TSelf, TOther, TResult}.op_Addition(TSelf, TOther)" />
    public static NativeCULong operator checked +(NativeCULong left, NativeCULong right) => new(checked(left._value + right._value));

    //
    // IAdditiveIdentity
    //

    /// <inheritdoc cref="IAdditiveIdentity{TSelf, TResult}.AdditiveIdentity" />
    static NativeCULong IAdditiveIdentity<NativeCULong, NativeCULong>.AdditiveIdentity => new((nuint)0);

    //
    // IBinaryInteger
    //

    /// <inheritdoc cref="IBinaryInteger{TSelf}.DivRem(TSelf, TSelf)" />
    public static (NativeCULong Quotient, NativeCULong Remainder) DivRem(NativeCULong left, NativeCULong right)
    {
        (NativeType quotient, NativeType remainder) = NativeType.DivRem(left._value, right._value);
        return (new NativeCULong(quotient), new NativeCULong(remainder));
    }

    /// <inheritdoc cref="IBinaryInteger{TSelf}.LeadingZeroCount(TSelf)" />
    public static NativeCULong LeadingZeroCount(NativeCULong value) => new(NativeType.LeadingZeroCount(value._value));

    /// <inheritdoc cref="IBinaryInteger{TSelf}.PopCount(TSelf)" />
    public static NativeCULong PopCount(NativeCULong value) => new(NativeType.PopCount(value._value));

    /// <inheritdoc cref="IBinaryInteger{TSelf}.RotateLeft(TSelf, int)" />
    public static NativeCULong RotateLeft(NativeCULong value, int rotateAmount) => new(NativeType.RotateLeft(value._value, rotateAmount));

    /// <inheritdoc cref="IBinaryInteger{TSelf}.RotateRight(TSelf, int)" />
    public static NativeCULong RotateRight(NativeCULong value, int rotateAmount) => new(NativeType.RotateRight(value._value, rotateAmount));

    /// <inheritdoc cref="IBinaryInteger{TSelf}.TrailingZeroCount(TSelf)" />
    public static NativeCULong TrailingZeroCount(NativeCULong value) => new(NativeType.TrailingZeroCount(value._value));

    /// <inheritdoc cref="IBinaryInteger{TSelf}.GetShortestBitLength()" />
    unsafe int IBinaryInteger<NativeCULong>.GetShortestBitLength()
    {
        NativeType value = _value;
        return (sizeof(NativeType) * 8) - BitOperations.LeadingZeroCount(value);
    }

    /// <inheritdoc cref="IBinaryInteger{TSelf}.GetByteCount()" />
    unsafe int IBinaryInteger<NativeCULong>.GetByteCount() => sizeof(NativeType);

    /// <inheritdoc cref="IBinaryInteger{TSelf}.TryWriteLittleEndian(Span{byte}, out int)" />
    unsafe bool IBinaryInteger<NativeCULong>.TryWriteLittleEndian(Span<byte> destination, out int bytesWritten)
    {
        if (destination.Length >= sizeof(NativeCULong))
        {
            NativeType value = BitConverter.IsLittleEndian ? _value : BinaryPrimitives.ReverseEndianness(_value);
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), value);

            bytesWritten = sizeof(NativeCULong);
            return true;
        }
        else
        {
            bytesWritten = 0;
            return false;
        }
    }

    /// <inheritdoc cref="IBinaryInteger{TSelf}.TryWriteBigEndian(Span{byte}, out int)" />
    unsafe bool IBinaryInteger<NativeCULong>.TryWriteBigEndian(Span<byte> destination, out int bytesWritten)
    {
        if (destination.Length >= sizeof(NativeCULong))
        {
            NativeType value = BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(_value) : _value;
            Unsafe.WriteUnaligned(ref MemoryMarshal.GetReference(destination), value);

            bytesWritten = sizeof(NativeCULong);
            return true;
        }
        else
        {
            bytesWritten = 0;
            return false;
        }
    }

    /// <inheritdoc cref="IBinaryInteger{TSelf}.TryReadLittleEndian(ReadOnlySpan{byte}, bool, out TSelf)" />
    static unsafe bool IBinaryInteger<NativeCULong>.TryReadLittleEndian(ReadOnlySpan<byte> source, bool isUnsigned, out NativeCULong value)
    {
        Unsafe.SkipInit(out value);

        if (source.Length < sizeof(NativeType))
        {
            return false;
        }

        NativeType result = Unsafe.ReadUnaligned<NativeType>(ref MemoryMarshal.GetReference(source));
        if (!BitConverter.IsLittleEndian)
        {
            result = BinaryPrimitives.ReverseEndianness(result);
        }

        value = new NativeCULong(result);
        return true;
    }

    /// <inheritdoc cref="IBinaryInteger{TSelf}.TryReadBigEndian(ReadOnlySpan{byte}, bool, out TSelf)" />
    static unsafe bool IBinaryInteger<NativeCULong>.TryReadBigEndian(ReadOnlySpan<byte> source, bool isUnsigned, out NativeCULong value)
    {
        Unsafe.SkipInit(out value);

        if (source.Length < sizeof(NativeType))
        {
            return false;
        }

        NativeType result = Unsafe.ReadUnaligned<NativeType>(ref MemoryMarshal.GetReference(source));
        if (BitConverter.IsLittleEndian)
        {
            result = BinaryPrimitives.ReverseEndianness(result);
        }

        value = new NativeCULong(result);
        return true;
    }

    //
    // IBinaryNumber
    //

    /// <inheritdoc cref="IBinaryNumber{TSelf}.IsPow2(TSelf)" />
    public static bool IsPow2(NativeCULong value) => NativeType.IsPow2(value._value);

    /// <inheritdoc cref="IBinaryNumber{TSelf}.Log2(TSelf)" />
    public static NativeCULong Log2(NativeCULong value) => new(NativeType.Log2(value._value));

    //
    // IBitwiseOperators
    //

    /// <inheritdoc cref="IBitwiseOperators{TSelf, TOther, TResult}.op_BitwiseAnd(TSelf, TOther)" />
    public static NativeCULong operator &(NativeCULong left, NativeCULong right) => new(left._value & right._value);

    /// <inheritdoc cref="IBitwiseOperators{TSelf, TOther, TResult}.op_BitwiseOr(TSelf, TOther)" />
    public static NativeCULong operator |(NativeCULong left, NativeCULong right) => new(left._value | right._value);

    /// <inheritdoc cref="IBitwiseOperators{TSelf, TOther, TResult}.op_ExclusiveOr(TSelf, TOther)" />
    public static NativeCULong operator ^(NativeCULong left, NativeCULong right) => new(left._value ^ right._value);

    /// <inheritdoc cref="IBitwiseOperators{TSelf, TOther, TResult}.op_OnesComplement(TSelf)" />
    public static NativeCULong operator ~(NativeCULong value) => new NativeCULong(~value._value);

    //
    // IComparable
    //

    public int CompareTo(object? value)
    {
        if (value is NativeCULong other)
        {
            return CompareTo(other);
        }
        return (value is null) ? 1 : throw new ArgumentException("Object must be of type NativeCULong.");
    }

    public int CompareTo(NativeCULong value) => _value.CompareTo(value._value);

    //
    // IComparisonOperators
    //

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther}.op_LessThan(TSelf, TOther)" />
    public static bool operator <(NativeCULong left, NativeCULong right) => left._value < right._value;

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther}.op_LessThanOrEqual(TSelf, TOther)" />
    public static bool operator <=(NativeCULong left, NativeCULong right) => left._value <= right._value;

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther}.op_GreaterThan(TSelf, TOther)" />
    public static bool operator >(NativeCULong left, NativeCULong right) => left._value > right._value;

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther}.op_GreaterThanOrEqual(TSelf, TOther)" />
    public static bool operator >=(NativeCULong left, NativeCULong right) => left._value >= right._value;

    //
    // IDecrementOperators
    //

    /// <inheritdoc cref="IDecrementOperators{TSelf}.op_Decrement(TSelf)" />
    public static NativeCULong operator --(NativeCULong value)
    {
        NativeType tmp = value._value;
        --tmp;
        return new NativeCULong(tmp);
    }

    /// <inheritdoc cref="IDecrementOperators{TSelf}.op_Decrement(TSelf)" />
    public static NativeCULong operator checked --(NativeCULong value)
    {
        NativeType tmp = value._value;

        checked
        {
            --tmp;
        }
        return new NativeCULong(tmp);
    }

    //
    // IDivisionOperators
    //

    /// <inheritdoc cref="IDivisionOperators{TSelf, TOther, TResult}.op_Division(TSelf, TOther)" />
    public static NativeCULong operator /(NativeCULong left, NativeCULong right) => new(left._value / right._value);

    /// <inheritdoc cref="IDivisionOperators{TSelf, TOther, TResult}.op_CheckedDivision(TSelf, TOther)" />
    static NativeCULong IDivisionOperators<NativeCULong, NativeCULong, NativeCULong>.operator checked /(NativeCULong left, NativeCULong right) => left / right;

    //
    // IEqualityOperators
    //

    /// <inheritdoc cref="IEqualityOperators{TSelf, TOther}.op_Equality(TSelf, TOther)" />
    public static bool operator ==(NativeCULong left, NativeCULong right) => left._value == right._value;

    /// <inheritdoc cref="IEqualityOperators{TSelf, TOther}.op_Inequality(TSelf, TOther)" />
    public static bool operator !=(NativeCULong left, NativeCULong right) => left._value != right._value;

    //
    // IFormattable
    //

    /// <inheritdoc cref="IFormattable.ToString(string?, IFormatProvider?)" />
    public string ToString(string? format, IFormatProvider? formatProvider) => _value.ToString(format, formatProvider);

    //
    // IIncrementOperators
    //

    /// <inheritdoc cref="IIncrementOperators{TSelf}.op_Increment(TSelf)" />
    public static NativeCULong operator ++(NativeCULong value)
    {
        NativeType tmp = value._value;
        ++tmp;
        return new NativeCULong(tmp);
    }

    /// <inheritdoc cref="IIncrementOperators{TSelf}.op_CheckedIncrement(TSelf)" />
    public static NativeCULong operator checked ++(NativeCULong value)
    {
        NativeType tmp = value._value;

        checked
        {
            ++tmp;
        }
        return new NativeCULong(tmp);
    }

    //
    // IMinMaxValue
    //

    /// <inheritdoc cref="IMinMaxValue{TSelf}.MinValue" />
    public static NativeCULong MinValue => new(NativeType.MinValue);

    /// <inheritdoc cref="IMinMaxValue{TSelf}.MaxValue" />
    public static NativeCULong MaxValue => new(NativeType.MaxValue);

    //
    // IModulusOperators
    //

    /// <inheritdoc cref="IModulusOperators{TSelf, TOther, TResult}.op_Modulus(TSelf, TOther)" />
    public static NativeCULong operator %(NativeCULong left, NativeCULong right) => new(left._value % right._value);

    //
    // IMultiplicativeIdentity
    //

    /// <inheritdoc cref="IMultiplicativeIdentity{TSelf, TResult}.MultiplicativeIdentity" />
    static NativeCULong IMultiplicativeIdentity<NativeCULong, NativeCULong>.MultiplicativeIdentity => new((NativeType)1);

    //
    // IMultiplyOperators
    //

    /// <inheritdoc cref="IMultiplyOperators{TSelf, TOther, TResult}.op_Multiply(TSelf, TOther)" />
    public static NativeCULong operator *(NativeCULong left, NativeCULong right) => new(left._value * right._value);

    /// <inheritdoc cref="IMultiplyOperators{TSelf, TOther, TResult}.op_CheckedMultiply(TSelf, TOther)" />
    public static NativeCULong operator checked *(NativeCULong left, NativeCULong right) => new(checked(left._value * right._value));

    //
    // INumber
    //

    /// <inheritdoc cref="INumber{TSelf}.Abs(TSelf)" />
    public static NativeCULong Abs(NativeCULong value) => value;

    /// <inheritdoc cref="INumber{TSelf}.Clamp(TSelf, TSelf, TSelf)" />
    public static NativeCULong Clamp(NativeCULong value, NativeCULong min, NativeCULong max) => new(NativeType.Clamp(value._value, min._value, max._value));

    /// <inheritdoc cref="INumber{TSelf}.CopySign(TSelf, TSelf)" />
    public static NativeCULong CopySign(NativeCULong value, NativeCULong sign) => value;

    /// <inheritdoc cref="INumber{TSelf}.CreateChecked{TOther}(TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static NativeCULong CreateChecked<TOther>(TOther value)
        where TOther : INumberBase<TOther> => new(NativeType.CreateChecked(value));

    /// <inheritdoc cref="INumber{TSelf}.CreateSaturating{TOther}(TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static NativeCULong CreateSaturating<TOther>(TOther value)
        where TOther : INumberBase<TOther> => new(NativeType.CreateSaturating(value));

    /// <inheritdoc cref="INumber{TSelf}.CreateTruncating{TOther}(TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static NativeCULong CreateTruncating<TOther>(TOther value)
        where TOther : INumberBase<TOther> => new(NativeType.CreateTruncating(value));

    /// <inheritdoc cref="INumber{TSelf}.IsNegative(TSelf)" />
    public static bool IsNegative(NativeCULong value) => false;

    /// <inheritdoc cref="INumber{TSelf}.Max(TSelf, TSelf)" />
    public static NativeCULong Max(NativeCULong x, NativeCULong y) => new(NativeType.Max(x._value, y._value));

    /// <inheritdoc cref="INumber{TSelf}.MaxMagnitude(TSelf, TSelf)" />
    public static NativeCULong MaxMagnitude(NativeCULong x, NativeCULong y) => Max(x, y);

    /// <inheritdoc cref="INumber{TSelf}.Min(TSelf, TSelf)" />
    public static NativeCULong Min(NativeCULong x, NativeCULong y) => new(NativeType.Min(x._value, y._value));

    /// <inheritdoc cref="INumber{TSelf}.MinMagnitude(TSelf, TSelf)" />
    public static NativeCULong MinMagnitude(NativeCULong x, NativeCULong y) => Min(x, y);

    /// <inheritdoc cref="INumber{TSelf}.Parse(string, NumberStyles, IFormatProvider?)" />
    public static NativeCULong Parse(string s, NumberStyles style, IFormatProvider? provider) => new(NativeType.Parse(s, style, provider));

    /// <inheritdoc cref="INumber{TSelf}.Parse(ReadOnlySpan{char}, NumberStyles, IFormatProvider?)" />
    public static NativeCULong Parse(ReadOnlySpan<char> s, NumberStyles style, IFormatProvider? provider) => new(NativeType.Parse(s, style, provider));

    /// <inheritdoc cref="INumber{TSelf}.Sign(TSelf)" />
    public static int Sign(NativeCULong value) => NativeType.Sign(value._value);

    /// <inheritdoc cref="INumber{TSelf}.TryCreate{TOther}(TOther, out TSelf)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryCreate<TOther>(TOther value, out NativeCULong result)
        where TOther : INumber<TOther>
    {
#if NET7_0_OR_GREATER && WINDOWS
        // .NET 7+ on Windows: use native uint.TryCreate
        if (uint.TryCreate(value, out uint temp))
        {
            result = new NativeCULong(temp);
            return true;
        }
        result = default;
        return false;

#elif WINDOWS
        // .NET 6 on Windows: convert through ulong and check range
        if (TOther.TryConvertToTruncating(value, out ulong tempUlong))
        {
            if (tempUlong > uint.MaxValue)
            {
                result = default;
                return false;
            }
            result = new NativeCULong((uint)tempUlong);
            return true;
        }
        result = default;
        return false;

#else
        // Unix (any .NET version): convert through ulong to nuint
        if (TOther.TryConvertToTruncating(value, out ulong tempUlong))
        {
            result = new NativeCULong((nuint)tempUlong);
            return true;
        }
        result = default;
        return false;
#endif
    }

    /// <inheritdoc cref="INumber{TSelf}.TryParse(string?, NumberStyles, IFormatProvider?, out TSelf)" />
    public static bool TryParse([NotNullWhen(true)] string? s, NumberStyles style, IFormatProvider? provider, out NativeCULong result)
    {
        Unsafe.SkipInit(out result);
        return NativeType.TryParse(s, style, provider, out Unsafe.As<NativeCULong, NativeType>(ref result));
    }

    /// <inheritdoc cref="INumber{TSelf}.TryParse(ReadOnlySpan{char}, NumberStyles, IFormatProvider?, out TSelf)" />
    public static bool TryParse(ReadOnlySpan<char> s, NumberStyles style, IFormatProvider? provider, out NativeCULong result)
    {
        Unsafe.SkipInit(out result);
        return NativeType.TryParse(s, style, provider, out Unsafe.As<NativeCULong, NativeType>(ref result));
    }

    //
    // INumberBase
    //

    /// <inheritdoc cref="INumberBase{TSelf}.One" />
    static NativeCULong INumberBase<NativeCULong>.One => new((NativeType)1);

    /// <inheritdoc cref="INumberBase{TSelf}.Zero" />
    static NativeCULong INumberBase<NativeCULong>.Zero => new((NativeType)0);

    /// <inheritdoc cref="INumberBase{TSelf}.Radix" />
    static int INumberBase<NativeCULong>.Radix => 2;

    /// <inheritdoc cref="INumberBase{TSelf}.IsCanonical(TSelf)" />
    static bool INumberBase<NativeCULong>.IsCanonical(NativeCULong value) => true;

    /// <inheritdoc cref="INumberBase{TSelf}.IsComplexNumber(TSelf)" />
    static bool INumberBase<NativeCULong>.IsComplexNumber(NativeCULong value) => false;

    /// <inheritdoc cref="INumberBase{TSelf}.IsEvenInteger(TSelf)" />
    static bool INumberBase<NativeCULong>.IsEvenInteger(NativeCULong value) => (value._value & (NativeType)1) == 0;

    /// <inheritdoc cref="INumberBase{TSelf}.IsFinite(TSelf)" />
    static bool INumberBase<NativeCULong>.IsFinite(NativeCULong value) => true;

    /// <inheritdoc cref="INumberBase{TSelf}.IsImaginaryNumber(TSelf)" />
    static bool INumberBase<NativeCULong>.IsImaginaryNumber(NativeCULong value) => false;

    /// <inheritdoc cref="INumberBase{TSelf}.IsInfinity(TSelf)" />
    static bool INumberBase<NativeCULong>.IsInfinity(NativeCULong value) => false;

    /// <inheritdoc cref="INumberBase{TSelf}.IsInteger(TSelf)" />
    static bool INumberBase<NativeCULong>.IsInteger(NativeCULong value) => true;

    /// <inheritdoc cref="INumberBase{TSelf}.IsNaN(TSelf)" />
    static bool INumberBase<NativeCULong>.IsNaN(NativeCULong value) => false;

    /// <inheritdoc cref="INumberBase{TSelf}.IsNegativeInfinity(TSelf)" />
    static bool INumberBase<NativeCULong>.IsNegativeInfinity(NativeCULong value) => false;

    /// <inheritdoc cref="INumberBase{TSelf}.IsNormal(TSelf)" />
    static bool INumberBase<NativeCULong>.IsNormal(NativeCULong value) => value._value != (NativeType)0;

    /// <inheritdoc cref="INumberBase{TSelf}.IsOddInteger(TSelf)" />
    static bool INumberBase<NativeCULong>.IsOddInteger(NativeCULong value) => (value._value & (NativeType)1) != 0;

    /// <inheritdoc cref="INumberBase{TSelf}.IsPositive(TSelf)" />
    static bool INumberBase<NativeCULong>.IsPositive(NativeCULong value) => true;

    /// <inheritdoc cref="INumberBase{TSelf}.IsPositiveInfinity(TSelf)" />
    static bool INumberBase<NativeCULong>.IsPositiveInfinity(NativeCULong value) => false;

    /// <inheritdoc cref="INumberBase{TSelf}.IsRealNumber(TSelf)" />
    static bool INumberBase<NativeCULong>.IsRealNumber(NativeCULong value) => true;

    /// <inheritdoc cref="INumberBase{TSelf}.IsSubnormal(TSelf)" />
    static bool INumberBase<NativeCULong>.IsSubnormal(NativeCULong value) => false;

    /// <inheritdoc cref="INumberBase{TSelf}.IsZero(TSelf)" />
    static bool INumberBase<NativeCULong>.IsZero(NativeCULong value) => value._value == (NativeType)0;

    /// <inheritdoc cref="INumberBase{TSelf}.MaxMagnitudeNumber(TSelf, TSelf)" />
    static NativeCULong INumberBase<NativeCULong>.MaxMagnitudeNumber(NativeCULong x, NativeCULong y) => Max(x, y);

    /// <inheritdoc cref="INumberBase{TSelf}.MinMagnitudeNumber(TSelf, TSelf)" />
    static NativeCULong INumberBase<NativeCULong>.MinMagnitudeNumber(NativeCULong x, NativeCULong y) => Min(x, y);

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertFromChecked{TOther}(TOther, out TSelf)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertFromChecked<TOther>(TOther value, out NativeCULong result)
    {
#if NET7_0_OR_GREATER && WINDOWS
        // .NET 7+ on Windows: use native uint.TryConvertFromChecked
        if (uint.TryConvertFromChecked(value, out uint temp))
        {
            result = new NativeCULong(temp);
            return true;
        }
        result = default;
        return false;

#elif WINDOWS
        // .NET 6 on Windows: convert through ulong with checked cast to uint
        if (TOther.TryConvertToChecked(value, out ulong tempUlong))
        {
            try
            {
                result = new NativeCULong(checked((uint)tempUlong));
                return true;
            }
            catch (OverflowException)
            {
                // Value exceeds uint.MaxValue
            }
        }
        result = default;
        return false;

#else
        // Unix (any .NET version): convert through ulong with checked cast to nuint
        if (TOther.TryConvertToChecked(value, out ulong tempUlong))
        {
            try
            {
                result = new NativeCULong(checked((nuint)tempUlong));
                return true;
            }
            catch (OverflowException)
            {
                // Value exceeds platform pointer size
            }
        }
        result = default;
        return false;
#endif
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertFromSaturating{TOther}(TOther, out TSelf)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertFromSaturating<TOther>(TOther value, out NativeCULong result)
    {
#if NET7_0_OR_GREATER && WINDOWS
        // .NET 7+ on Windows: use native uint.TryConvertFromSaturating
        if (uint.TryConvertFromSaturating(value, out uint temp))
        {
            result = new NativeCULong(temp);
            return true;
        }
        result = default;
        return false;

#elif WINDOWS
        // .NET 6 on Windows: convert through ulong and saturate to uint.MaxValue
        if (TOther.TryConvertToSaturating(value, out ulong tempUlong))
        {
            uint saturated = tempUlong > uint.MaxValue ? uint.MaxValue : (uint)tempUlong;
            result = new NativeCULong(saturated);
            return true;
        }
        result = default;
        return false;

#else
        // Unix (any .NET version): convert through ulong and saturate to nuint.MaxValue
        if (TOther.TryConvertToSaturating(value, out ulong tempUlong))
        {
            nuint saturated = tempUlong > nuint.MaxValue ? nuint.MaxValue : (nuint)tempUlong;
            result = new NativeCULong(saturated);
            return true;
        }
        result = default;
        return false;
#endif
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertFromTruncating{TOther}(TOther, out TSelf)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertFromTruncating<TOther>(TOther value, out NativeCULong result)
    {
#if NET7_0_OR_GREATER && WINDOWS
        // .NET 7+ on Windows: use native uint.TryConvertFromTruncating
        if (uint.TryConvertFromTruncating(value, out uint temp))
        {
            result = new NativeCULong(temp);
            return true;
        }
        result = default;
        return false;

#elif WINDOWS
        // .NET 6 on Windows: convert through ulong and truncate to 32 bits
        if (TOther.TryConvertToTruncating(value, out ulong tempUlong))
        {
            result = new NativeCULong((uint)tempUlong);
            return true;
        }
        result = default;
        return false;

#else
        // Unix (any .NET version): convert through ulong and truncate to platform size
        if (TOther.TryConvertToTruncating(value, out ulong tempUlong))
        {
            result = new NativeCULong((nuint)tempUlong);
            return true;
        }
        result = default;
        return false;
#endif
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertToChecked{TOther}(TSelf, out TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertToChecked<TOther>(NativeCULong value, [MaybeNullWhen(false)] out TOther result)
    {
#if NET7_0_OR_GREATER && WINDOWS
        // .NET 7+ on Windows: use native uint.TryConvertToChecked
        return uint.TryConvertToChecked(value._value, out result);
#else
        // .NET 6 or Unix: convert _value to ulong, then to TOther
        return TOther.TryConvertFromChecked((ulong)value._value, out result);
#endif
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertToSaturating{TOther}(TSelf, out TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertToSaturating<TOther>(NativeCULong value, [MaybeNullWhen(false)] out TOther result)
    {
#if NET7_0_OR_GREATER && WINDOWS
        // .NET 7+ on Windows: use native uint.TryConvertToSaturating
        return uint.TryConvertToSaturating(value._value, out result);
#else
        // .NET 6 or Unix: convert _value to ulong, then to TOther
        return TOther.TryConvertFromSaturating((ulong)value._value, out result);
#endif
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertToTruncating{TOther}(TSelf, out TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertToTruncating<TOther>(NativeCULong value, [MaybeNullWhen(false)] out TOther result)
    {
#if NET7_0_OR_GREATER && WINDOWS
        // .NET 7+ on Windows: use native uint.TryConvertToTruncating
        return uint.TryConvertToTruncating(value._value, out result);
#else
        // .NET 6 or Unix: convert _value to ulong, then to TOther
        return TOther.TryConvertFromTruncating((ulong)value._value, out result);
#endif
    }

    //
    // IParsable
    //

    /// <inheritdoc cref="IParsable{TSelf}.Parse(string, IFormatProvider?)" />
    public static NativeCULong Parse(string s, IFormatProvider? provider) => Parse(s, NumberStyles.Integer, provider);

    /// <inheritdoc cref="IParsable{TSelf}.TryParse(string?, IFormatProvider?, out TSelf)" />
    public static bool TryParse([NotNullWhen(true)] string? s, IFormatProvider? provider, out NativeCULong result) => TryParse(s, NumberStyles.Integer, provider, out result);

    //
    // IShiftOperators
    //

    /// <inheritdoc cref="IShiftOperators{TSelf, TResult}.op_LeftShift(TSelf, int)" />
    public static NativeCULong operator <<(NativeCULong value, int shiftAmount) => new(value._value << shiftAmount);

    /// <inheritdoc cref="IShiftOperators{TSelf, TResult}.op_RightShift(TSelf, int)" />
    public static NativeCULong operator >>(NativeCULong value, int shiftAmount) => new(value._value >> shiftAmount);

    /// <inheritdoc cref="IShiftOperators{TSelf, TResult}.op_UnsignedRightShift(TSelf, int)" />
    public static NativeCULong operator >>>(NativeCULong value, int shiftAmount) => new(value._value >>> shiftAmount);

    //
    // ISpanFormattable
    //

    /// <inheritdoc cref="ISpanFormattable.TryFormat(Span{char}, out int, ReadOnlySpan{char}, IFormatProvider?)" />
    public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider) => _value.TryFormat(destination, out charsWritten, format, provider);

    //
    // ISpanParsable
    //

    /// <inheritdoc cref="ISpanParsable{TSelf}.Parse(ReadOnlySpan{char}, IFormatProvider?)" />
    public static NativeCULong Parse(ReadOnlySpan<char> s, IFormatProvider? provider) => Parse(s, NumberStyles.Integer, provider);

    /// <inheritdoc cref="ISpanParsable{TSelf}.TryParse(ReadOnlySpan{char}, IFormatProvider?, out TSelf)" />
    public static bool TryParse(ReadOnlySpan<char> s, IFormatProvider? provider, out NativeCULong result) => TryParse(s, NumberStyles.Integer, provider, out result);

    //
    // ISubtractionOperators
    //

    /// <inheritdoc cref="ISubtractionOperators{TSelf, TOther, TResult}.op_Subtraction(TSelf, TOther)" />
    public static NativeCULong operator -(NativeCULong left, NativeCULong right) => new(left._value - right._value);

    /// <inheritdoc cref="ISubtractionOperators{TSelf, TOther, TResult}.op_CheckedSubtraction(TSelf, TOther)" />
    public static NativeCULong operator checked -(NativeCULong left, NativeCULong right) => new(checked(left._value - right._value));

    //
    // IUnaryNegationOperators
    //

    /// <inheritdoc cref="IUnaryNegationOperators{TSelf, TResult}.op_UnaryNegation(TSelf)" />
    static NativeCULong IUnaryNegationOperators<NativeCULong, NativeCULong>.operator -(NativeCULong value) => new(0 - value._value);

    /// <inheritdoc cref="IUnaryNegationOperators{TSelf, TResult}.op_CheckedUnaryNegation(TSelf)" />
    static NativeCULong IUnaryNegationOperators<NativeCULong, NativeCULong>.operator checked -(NativeCULong value) => new(checked(0 - value._value));

    //
    // IUnaryPlusOperators
    //

    /// <inheritdoc cref="IUnaryPlusOperators{TSelf, TResult}.op_UnaryPlus(TSelf)" />
    public static NativeCULong operator +(NativeCULong value) => value;

    //
    // ISerializable
    //

    /// <summary>
    /// Initializes a new instance of the <see cref="NativeCULong"/> struct from serialized data.
    /// </summary>
    /// <param name="info">The serialization info.</param>
    /// <param name="context">The streaming context.</param>
    private NativeCULong(SerializationInfo info, StreamingContext context)
    {
        ArgumentNullException.ThrowIfNull(info);

        _value = (NativeType)info.GetValue(nameof(_value), typeof(NativeType))!;
    }

    /// <inheritdoc cref="ISerializable.GetObjectData(SerializationInfo, StreamingContext)" />
    void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
    {
        ArgumentNullException.ThrowIfNull(info);

        info.AddValue(nameof(_value), _value);
    }
}
