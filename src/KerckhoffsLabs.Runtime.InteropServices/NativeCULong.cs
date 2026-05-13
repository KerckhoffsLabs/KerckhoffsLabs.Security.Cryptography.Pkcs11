// Licensed under the MIT License

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
/// <remarks>
/// The BCL ships <see cref="System.Runtime.InteropServices.CULong"/> (added in .NET 6) with the same
/// 32-/64-bit platform contract, but it is a bare struct wrapper exposing only a <see cref="System.Runtime.InteropServices.CULong.Value"/>
/// property — it does not implement <see cref="IBinaryInteger{TSelf}"/>, the generic-math interface
/// hierarchy, or <see cref="ISpanFormattable"/>. <see cref="NativeCULong"/> implements all of those,
/// so it can be used directly in generic numeric code (e.g. <c>T : IBinaryInteger&lt;T&gt;</c>) and in
/// P/Invoke marshalling without an additional unwrap step.
/// </remarks>
[CLSCompliant(false)]
public readonly struct NativeCULong
    : IEquatable<NativeCULong>,
      IComparable,
      IComparable<NativeCULong>,
      ISpanFormattable,
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
#if WINDOWS
        // 32-bit storage; throws when value exceeds uint.MaxValue (only possible on 64-bit Windows).
        _value = checked((uint)value);
#else
        // Storage is nuint; no narrowing needed.
        _value = value;
#endif
    }

    /// <summary>
    /// The underlying integer value of this instance.
    /// </summary>
    public nuint Value => _value;

    // ---- Explicit cast operators ----
    //
    // Each lossy conversion ships as a pair: the plain `operator` wraps/truncates silently,
    // and the paired `operator checked` throws OverflowException on out-of-range values.
    // The C# compiler routes calls in a `checked` context — including the project-wide
    // <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow> setting in the csproj —
    // to the `operator checked` overload. Inside the `unchecked` body itself, the
    // `unchecked(...)` literal makes the behavior explicit even when the call site is
    // compiled `checked`.
    //
    // Conversions that are always exact on every supported platform (NativeCULong ← uint,
    // NativeCULong → ulong, NativeCULong → nuint) only have the plain operator — no
    // `operator checked` is needed.
    //
    // The generic-math path is also available: NativeCULong.CreateChecked(int) and
    // int.CreateChecked(nativeCULong) work via INumberBase&lt;T&gt;.

    /// <summary>Converts an <see cref="int"/> to a <see cref="NativeCULong"/>. Negative values wrap silently; the paired <c>checked</c> operator throws.</summary>
    public static explicit operator NativeCULong(int   value) => new(unchecked((uint)value));
    /// <summary>Converts a <see cref="uint"/> to a <see cref="NativeCULong"/>. Always exact; widens to <see cref="nuint"/> storage on Unix.</summary>
    public static explicit operator NativeCULong(uint  value) => new(value);
    /// <summary>Converts a <see cref="long"/> to a <see cref="NativeCULong"/>. Out-of-range values wrap silently; the paired <c>checked</c> operator throws.</summary>
    public static explicit operator NativeCULong(long  value) => new(unchecked((nuint)value));
    /// <summary>Converts a <see cref="ulong"/> to a <see cref="NativeCULong"/>. On Windows (32-bit storage), values above <see cref="uint.MaxValue"/> wrap silently; the paired <c>checked</c> operator throws. On Unix (64-bit storage), always exact.</summary>
    public static explicit operator NativeCULong(ulong value) => new(unchecked((nuint)value));
    /// <summary>Converts an <see cref="nuint"/> to a <see cref="NativeCULong"/>. On Windows (32-bit storage), values above <see cref="uint.MaxValue"/> wrap silently. On Unix (64-bit storage), always exact.</summary>
    public static explicit operator NativeCULong(nuint value) => new(value);

    /// <summary>Converts an <see cref="int"/> to a <see cref="NativeCULong"/>. Throws <see cref="System.OverflowException"/> on negative values.</summary>
    public static explicit operator checked NativeCULong(int   value) => new(checked((uint)value));
    /// <summary>Converts a <see cref="long"/> to a <see cref="NativeCULong"/>. Throws <see cref="System.OverflowException"/> on out-of-range values.</summary>
    public static explicit operator checked NativeCULong(long  value) => new(checked((nuint)value));
    /// <summary>Converts a <see cref="ulong"/> to a <see cref="NativeCULong"/>. On Windows (32-bit storage), throws <see cref="System.OverflowException"/> on values above <see cref="uint.MaxValue"/>. On Unix (64-bit storage), always succeeds.</summary>
    public static explicit operator checked NativeCULong(ulong value) => new(checked((nuint)value));

    /// <summary>Converts a <see cref="NativeCULong"/> to an <see cref="int"/>. Values above <see cref="int.MaxValue"/> wrap to negative silently; the paired <c>checked</c> operator throws.</summary>
    public static explicit operator int   (NativeCULong value) => unchecked((int)value._value);
    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="uint"/>. On Unix (64-bit storage), values above <see cref="uint.MaxValue"/> truncate silently; the paired <c>checked</c> operator throws. On Windows (32-bit storage), always exact.</summary>
    public static explicit operator uint  (NativeCULong value) => unchecked((uint)value._value);
    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="long"/>. On Unix (64-bit storage), values above <see cref="long.MaxValue"/> wrap to negative silently; the paired <c>checked</c> operator throws. On Windows (32-bit storage), always exact.</summary>
    public static explicit operator long  (NativeCULong value) => unchecked((long)value._value);
    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="ulong"/>. Always exact.</summary>
    public static explicit operator ulong (NativeCULong value) => unchecked((ulong)value._value);
    /// <summary>Converts a <see cref="NativeCULong"/> to an <see cref="nuint"/>. Always exact.</summary>
    public static explicit operator nuint (NativeCULong value) => value._value;

    /// <summary>Converts a <see cref="NativeCULong"/> to an <see cref="int"/>. Throws <see cref="System.OverflowException"/> on values above <see cref="int.MaxValue"/>.</summary>
    public static explicit operator checked int   (NativeCULong value) => checked((int)value._value);
    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="uint"/>. On Unix (64-bit storage), throws <see cref="System.OverflowException"/> on values above <see cref="uint.MaxValue"/>. On Windows (32-bit storage), always succeeds.</summary>
    public static explicit operator checked uint  (NativeCULong value) => checked((uint)value._value);
    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="long"/>. On Unix (64-bit storage), throws <see cref="System.OverflowException"/> on values above <see cref="long.MaxValue"/>. On Windows (32-bit storage), always succeeds.</summary>
    public static explicit operator checked long  (NativeCULong value) => checked((long)value._value);
    /// <summary>Converts a <see cref="NativeCULong"/> to a <see cref="ulong"/>. Always succeeds (the conversion is exact on every supported platform).</summary>
    public static explicit operator checked ulong (NativeCULong value) => checked((ulong)value._value);

    /// <summary>
    /// Returns a value indicating whether this instance is equal to a specified object.
    /// </summary>
    /// <param name="obj">An object to compare with this instance.</param>
    /// <returns><c>true</c> if <paramref name="obj"/> is an instance of <see cref="NativeCULong"/> and equals the value of this instance; otherwise, <c>false</c>.</returns>
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is NativeCULong other && Equals(other);

    /// <summary>
    /// Returns a value indicating whether this instance is equal to a specified <see cref="NativeCULong"/> value.
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
    public static NativeCULong operator +(NativeCULong left, NativeCULong right) => new(unchecked(left._value + right._value));

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
    public static NativeCULong operator ~(NativeCULong value) => new(~value._value);

    //
    // IComparable
    //

    public int CompareTo(object? value)
    {
        if (value is NativeCULong other)
        {
            return CompareTo(other);
        }
        return (value is null) ? 1 : throw new ArgumentException("Object must be of type NativeCULong.", nameof(value));
    }

    public int CompareTo(NativeCULong value) => _value.CompareTo(value._value);

    //
    // IComparisonOperators
    //

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther, TResult}.op_LessThan(TSelf, TOther)" />
    public static bool operator <(NativeCULong left, NativeCULong right) => left._value < right._value;

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther, TResult}.op_LessThanOrEqual(TSelf, TOther)" />
    public static bool operator <=(NativeCULong left, NativeCULong right) => left._value <= right._value;

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther, TResult}.op_GreaterThan(TSelf, TOther)" />
    public static bool operator >(NativeCULong left, NativeCULong right) => left._value > right._value;

    /// <inheritdoc cref="IComparisonOperators{TSelf, TOther, TResult}.op_GreaterThanOrEqual(TSelf, TOther)" />
    public static bool operator >=(NativeCULong left, NativeCULong right) => left._value >= right._value;

    //
    // IDecrementOperators
    //

    /// <inheritdoc cref="IDecrementOperators{TSelf}.op_Decrement(TSelf)" />
    public static NativeCULong operator --(NativeCULong value)
    {
        NativeType tmp = value._value;
        unchecked { --tmp; }
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

    /// <inheritdoc cref="IEqualityOperators{TSelf, TOther, TResult}.op_Equality(TSelf, TOther)" />
    public static bool operator ==(NativeCULong left, NativeCULong right) => left._value == right._value;

    /// <inheritdoc cref="IEqualityOperators{TSelf, TOther, TResult}.op_Inequality(TSelf, TOther)" />
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
        unchecked { ++tmp; }
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
    public static NativeCULong operator *(NativeCULong left, NativeCULong right) => new(unchecked(left._value * right._value));

    /// <inheritdoc cref="IMultiplyOperators{TSelf, TOther, TResult}.op_CheckedMultiply(TSelf, TOther)" />
    public static NativeCULong operator checked *(NativeCULong left, NativeCULong right) => new(checked(left._value * right._value));

    //
    // INumber
    //

    /// <summary>Returns the absolute value of <paramref name="value"/>. For the unsigned <see cref="NativeCULong"/> type this is the identity function.</summary>
    /// <param name="value">The value.</param>
    /// <returns><paramref name="value"/> unchanged.</returns>
    public static NativeCULong Abs(NativeCULong value) => value;

    /// <inheritdoc cref="INumber{TSelf}.Clamp(TSelf, TSelf, TSelf)" />
    public static NativeCULong Clamp(NativeCULong value, NativeCULong min, NativeCULong max) => new(NativeType.Clamp(value._value, min._value, max._value));

    /// <inheritdoc cref="INumber{TSelf}.CopySign(TSelf, TSelf)" />
    public static NativeCULong CopySign(NativeCULong value, NativeCULong sign) => value;

    /// <summary>Converts <paramref name="value"/> to a <see cref="NativeCULong"/>, throwing <see cref="OverflowException"/> if the value is outside the representable range.</summary>
    /// <typeparam name="TOther">The type of the source value.</typeparam>
    /// <param name="value">The value to convert.</param>
    /// <returns>The converted <see cref="NativeCULong"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static NativeCULong CreateChecked<TOther>(TOther value)
        where TOther : INumberBase<TOther> => new(NativeType.CreateChecked(value));

    /// <summary>Converts <paramref name="value"/> to a <see cref="NativeCULong"/>, saturating at <see cref="MinValue"/> or <see cref="MaxValue"/> if the value is outside the representable range.</summary>
    /// <typeparam name="TOther">The type of the source value.</typeparam>
    /// <param name="value">The value to convert.</param>
    /// <returns>The converted <see cref="NativeCULong"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static NativeCULong CreateSaturating<TOther>(TOther value)
        where TOther : INumberBase<TOther> => new(NativeType.CreateSaturating(value));

    /// <summary>Converts <paramref name="value"/> to a <see cref="NativeCULong"/>, truncating any bits that do not fit in the representable range.</summary>
    /// <typeparam name="TOther">The type of the source value.</typeparam>
    /// <param name="value">The value to convert.</param>
    /// <returns>The converted <see cref="NativeCULong"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static NativeCULong CreateTruncating<TOther>(TOther value)
        where TOther : INumberBase<TOther> => new(NativeType.CreateTruncating(value));

    /// <summary>Always returns <c>false</c>; <see cref="NativeCULong"/> is an unsigned type and can never be negative.</summary>
    /// <param name="value">The value (ignored).</param>
    /// <returns><c>false</c>.</returns>
    public static bool IsNegative(NativeCULong value) => false;

    /// <inheritdoc cref="INumber{TSelf}.Max(TSelf, TSelf)" />
    public static NativeCULong Max(NativeCULong x, NativeCULong y) => new(NativeType.Max(x._value, y._value));

    /// <summary>Returns the value with the larger magnitude. For the unsigned <see cref="NativeCULong"/> type this is equivalent to <see cref="Max(NativeCULong, NativeCULong)"/>.</summary>
    /// <param name="x">The first value.</param>
    /// <param name="y">The second value.</param>
    /// <returns>The larger of <paramref name="x"/> and <paramref name="y"/>.</returns>
    public static NativeCULong MaxMagnitude(NativeCULong x, NativeCULong y) => Max(x, y);

    /// <inheritdoc cref="INumber{TSelf}.Min(TSelf, TSelf)" />
    public static NativeCULong Min(NativeCULong x, NativeCULong y) => new(NativeType.Min(x._value, y._value));

    /// <summary>Returns the value with the smaller magnitude. For the unsigned <see cref="NativeCULong"/> type this is equivalent to <see cref="Min(NativeCULong, NativeCULong)"/>.</summary>
    /// <param name="x">The first value.</param>
    /// <param name="y">The second value.</param>
    /// <returns>The smaller of <paramref name="x"/> and <paramref name="y"/>.</returns>
    public static NativeCULong MinMagnitude(NativeCULong x, NativeCULong y) => Min(x, y);

    /// <summary>Parses a string representation of an integer into a <see cref="NativeCULong"/> using the specified <see cref="System.Globalization.NumberStyles"/> and format provider.</summary>
    /// <param name="s">The string to parse.</param>
    /// <param name="style">A bitwise combination of <see cref="System.Globalization.NumberStyles"/> values that indicates the permitted format of <paramref name="s"/>.</param>
    /// <param name="provider">An object that supplies culture-specific formatting information.</param>
    /// <returns>The parsed <see cref="NativeCULong"/>.</returns>
    public static NativeCULong Parse(string s, NumberStyles style, IFormatProvider? provider) => new(NativeType.Parse(s, style, provider));

    /// <summary>Parses a span of characters representing an integer into a <see cref="NativeCULong"/> using the specified <see cref="System.Globalization.NumberStyles"/> and format provider.</summary>
    /// <param name="s">The span to parse.</param>
    /// <param name="style">A bitwise combination of <see cref="System.Globalization.NumberStyles"/> values that indicates the permitted format of <paramref name="s"/>.</param>
    /// <param name="provider">An object that supplies culture-specific formatting information.</param>
    /// <returns>The parsed <see cref="NativeCULong"/>.</returns>
    public static NativeCULong Parse(ReadOnlySpan<char> s, NumberStyles style, IFormatProvider? provider) => new(NativeType.Parse(s, style, provider));

    /// <inheritdoc cref="INumber{TSelf}.Sign(TSelf)" />
    public static int Sign(NativeCULong value) => NativeType.Sign(value._value);

    /// <summary>Attempts to convert <paramref name="value"/> to a <see cref="NativeCULong"/>. Returns <c>true</c> and sets <paramref name="result"/> on success; returns <c>false</c> and sets <paramref name="result"/> to <c>default</c> if the value is outside the representable range.</summary>
    /// <typeparam name="TOther">The type of the source value.</typeparam>
    /// <param name="value">The value to convert.</param>
    /// <param name="result">When this method returns, contains the converted value on success, or <c>default</c> on failure.</param>
    /// <returns><c>true</c> if the conversion succeeded; otherwise, <c>false</c>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryCreate<TOther>(TOther value, out NativeCULong result)
        where TOther : INumber<TOther>
    {
        // TryCreate has truncating semantics (its replacement, CreateChecked, is the
        // throwing variant). Convert TOther → ulong via the BCL dispatch, then narrow
        // to storage width without overflow checks.
        // Identity short-circuit: ulong.TryConvertToTruncating<ulong> returns false
        // (BCL narrow-table omits identity); handle ulong source directly so the
        // dispatch doesn't drop it.
        if (typeof(TOther) == typeof(ulong))
        {
            ulong v = (ulong)(object)value!;
            result = new NativeCULong(unchecked((NativeType)v));
            return true;
        }
        if (TOther.TryConvertToTruncating(value, out ulong tempUlong))
        {
            result = new NativeCULong(unchecked((NativeType)tempUlong));
            return true;
        }
        result = default;
        return false;
    }

    /// <summary>Attempts to parse a string as a <see cref="NativeCULong"/> using the specified <see cref="System.Globalization.NumberStyles"/> and format provider. Returns <c>true</c> and sets <paramref name="result"/> on success.</summary>
    /// <param name="s">The string to parse.</param>
    /// <param name="style">A bitwise combination of <see cref="System.Globalization.NumberStyles"/> values.</param>
    /// <param name="provider">An object that supplies culture-specific formatting information.</param>
    /// <param name="result">When this method returns, contains the parsed value on success, or <c>default</c> on failure.</param>
    /// <returns><c>true</c> if <paramref name="s"/> was parsed successfully; otherwise, <c>false</c>.</returns>
    public static bool TryParse([NotNullWhen(true)] string? s, NumberStyles style, IFormatProvider? provider, out NativeCULong result)
    {
        Unsafe.SkipInit(out result);
        return NativeType.TryParse(s, style, provider, out Unsafe.As<NativeCULong, NativeType>(ref result));
    }

    /// <summary>Attempts to parse a span of characters as a <see cref="NativeCULong"/> using the specified <see cref="System.Globalization.NumberStyles"/> and format provider. Returns <c>true</c> and sets <paramref name="result"/> on success.</summary>
    /// <param name="s">The span to parse.</param>
    /// <param name="style">A bitwise combination of <see cref="System.Globalization.NumberStyles"/> values.</param>
    /// <param name="provider">An object that supplies culture-specific formatting information.</param>
    /// <param name="result">When this method returns, contains the parsed value on success, or <c>default</c> on failure.</param>
    /// <returns><c>true</c> if <paramref name="s"/> was parsed successfully; otherwise, <c>false</c>.</returns>
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

    // The inbound TryConvertFrom* methods route TOther → ulong via the BCL's
    // INumberBase dispatch (TOther.TryConvertToX), then narrow ulong → storage with
    // the appropriate semantics. NativeType is uint on Windows (32-bit storage) and
    // nuint on Unix; using it lets a single body cover both platforms.

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertFromChecked{TOther}(TOther, out TSelf)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertFromChecked<TOther>(TOther value, out NativeCULong result)
    {
        if (typeof(TOther) == typeof(ulong))
        {
            ulong v = (ulong)(object)value!;
            result = new NativeCULong(checked((NativeType)v));
            return true;
        }
        if (TOther.TryConvertToChecked(value, out ulong tempUlong))
        {
            // checked narrow throws OverflowException if value exceeds storage width.
            result = new NativeCULong(checked((NativeType)tempUlong));
            return true;
        }
        result = default;
        return false;
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertFromSaturating{TOther}(TOther, out TSelf)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertFromSaturating<TOther>(TOther value, out NativeCULong result)
    {
        if (typeof(TOther) == typeof(ulong))
        {
            ulong v = (ulong)(object)value!;
            NativeType saturated = v > NativeType.MaxValue ? NativeType.MaxValue : (NativeType)v;
            result = new NativeCULong(saturated);
            return true;
        }
        if (TOther.TryConvertToSaturating(value, out ulong tempUlong))
        {
            NativeType saturated = tempUlong > NativeType.MaxValue
                ? NativeType.MaxValue
                : (NativeType)tempUlong;
            result = new NativeCULong(saturated);
            return true;
        }
        result = default;
        return false;
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertFromTruncating{TOther}(TOther, out TSelf)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertFromTruncating<TOther>(TOther value, out NativeCULong result)
    {
        if (typeof(TOther) == typeof(ulong))
        {
            ulong v = (ulong)(object)value!;
            result = new NativeCULong(unchecked((NativeType)v));
            return true;
        }
        if (TOther.TryConvertToTruncating(value, out ulong tempUlong))
        {
            result = new NativeCULong(unchecked((NativeType)tempUlong));
            return true;
        }
        result = default;
        return false;
    }

    // The outbound TryConvertTo* methods dispatch through TWO paths:
    //   1) For narrowing toward a signed type (sbyte, short, int, long, nint, Int128)
    //      we perform the cast ourselves. This is necessary because the BCL signed
    //      types' TryConvertFromX tables don't list ulong as a recognized source —
    //      e.g. int.TryConvertFromChecked<ulong> returns false, which would otherwise
    //      cause CreateChecked to throw NotSupportedException for an in-range value.
    //   2) For everything else (byte, ushort, uint, ulong, UInt128, nuint, char,
    //      decimal, Half, float, double) we delegate to TOther.TryConvertFromX —
    //      those types' From tables do recognize ulong as a source.

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertToChecked{TOther}(TSelf, out TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertToChecked<TOther>(NativeCULong value, [MaybeNullWhen(false)] out TOther result)
    {
        ulong v = (ulong)value._value;

        if (typeof(TOther) == typeof(sbyte))  { sbyte  r = checked((sbyte)v);  result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(short))  { short  r = checked((short)v);  result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(int))    { int    r = checked((int)v);    result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(long))   { long   r = checked((long)v);   result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(nint))   { nint   r = checked((nint)v);   result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(Int128)) { Int128 r = v;                  result = (TOther)(object)r; return true; }

        return TOther.TryConvertFromChecked(v, out result);
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertToSaturating{TOther}(TSelf, out TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertToSaturating<TOther>(NativeCULong value, [MaybeNullWhen(false)] out TOther result)
    {
        ulong v = (ulong)value._value;

        // Ulong is non-negative, so only the upper bound can saturate.
        if (typeof(TOther) == typeof(sbyte))  { sbyte  r = v > (ulong)sbyte.MaxValue ? sbyte.MaxValue : (sbyte)v; result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(short))  { short  r = v > (ulong)short.MaxValue ? short.MaxValue : (short)v; result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(int))    { int    r = v > int.MaxValue           ? int.MaxValue   : (int)v;   result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(long))   { long   r = v > long.MaxValue          ? long.MaxValue  : (long)v;  result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(nint))   { nint   r = v > (ulong)nint.MaxValue   ? nint.MaxValue  : (nint)v;  result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(Int128)) { Int128 r = v;                                                     result = (TOther)(object)r; return true; }

        return TOther.TryConvertFromSaturating(v, out result);
    }

    /// <inheritdoc cref="INumberBase{TSelf}.TryConvertToTruncating{TOther}(TSelf, out TOther)" />
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static bool INumberBase<NativeCULong>.TryConvertToTruncating<TOther>(NativeCULong value, [MaybeNullWhen(false)] out TOther result)
    {
        ulong v = (ulong)value._value;

        if (typeof(TOther) == typeof(sbyte))  { sbyte  r = unchecked((sbyte)v);  result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(short))  { short  r = unchecked((short)v);  result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(int))    { int    r = unchecked((int)v);    result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(long))   { long   r = unchecked((long)v);   result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(nint))   { nint   r = unchecked((nint)v);   result = (TOther)(object)r; return true; }
        if (typeof(TOther) == typeof(Int128)) { Int128 r = v;                    result = (TOther)(object)r; return true; }

        return TOther.TryConvertFromTruncating(v, out result);
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

    /// <inheritdoc cref="IShiftOperators{TSelf, TOther, TResult}.op_LeftShift(TSelf, TOther)" />
    public static NativeCULong operator <<(NativeCULong value, int shiftAmount) => new(value._value << shiftAmount);

    /// <inheritdoc cref="IShiftOperators{TSelf, TOther, TResult}.op_RightShift(TSelf, TOther)" />
    public static NativeCULong operator >>(NativeCULong value, int shiftAmount) => new(value._value >> shiftAmount);

    /// <inheritdoc cref="IShiftOperators{TSelf, TOther, TResult}.op_UnsignedRightShift(TSelf, TOther)" />
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
    public static NativeCULong operator -(NativeCULong left, NativeCULong right) => new(unchecked(left._value - right._value));

    /// <inheritdoc cref="ISubtractionOperators{TSelf, TOther, TResult}.op_CheckedSubtraction(TSelf, TOther)" />
    public static NativeCULong operator checked -(NativeCULong left, NativeCULong right) => new(checked(left._value - right._value));

    //
    // IUnaryNegationOperators
    //

    /// <inheritdoc cref="IUnaryNegationOperators{TSelf, TResult}.op_UnaryNegation(TSelf)" />
    static NativeCULong IUnaryNegationOperators<NativeCULong, NativeCULong>.operator -(NativeCULong value) => new(unchecked(0 - value._value));

    /// <inheritdoc cref="IUnaryNegationOperators{TSelf, TResult}.op_CheckedUnaryNegation(TSelf)" />
    static NativeCULong IUnaryNegationOperators<NativeCULong, NativeCULong>.operator checked -(NativeCULong value) => new(checked(0 - value._value));

    //
    // IUnaryPlusOperators
    //

    /// <inheritdoc cref="IUnaryPlusOperators{TSelf, TResult}.op_UnaryPlus(TSelf)" />
    public static NativeCULong operator +(NativeCULong value) => value;
}
