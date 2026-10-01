using System.Security.Cryptography;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.Algorithms;

/// <summary>
/// Shared nonce- and tag-size checks for the AEAD wrappers, so each adapter enforces its
/// <see cref="KeySizes"/> the same way and throws the same <see cref="ArgumentException"/> shape.
/// </summary>
internal static class AeadSizes
{
    /// <summary>
    /// Returns <paramref name="size"/> if it is one of <paramref name="legal"/>; otherwise throws an
    /// <see cref="ArgumentException"/> for <paramref name="paramName"/>.
    /// </summary>
    /// <param name="legal">The sizes allowed, in bytes.</param>
    /// <param name="size">The size to check, in bytes.</param>
    /// <param name="what">What is being sized, for the message (e.g. <c>"Nonce length"</c>).</param>
    /// <param name="paramName">The caller's parameter that carries the size.</param>
    public static int RequireLegal(KeySizes legal, int size, string what, string paramName)
    {
        if (size < legal.MinSize || size > legal.MaxSize
            || (legal.SkipSize > 0 && (size - legal.MinSize) % legal.SkipSize != 0))
            throw new ArgumentException(
                $"{what} must be between {legal.MinSize} and {legal.MaxSize} bytes (step {legal.SkipSize}); got {size}.",
                paramName);
        return size;
    }

    /// <summary>
    /// Throws an <see cref="ArgumentException"/> for <paramref name="tag"/> unless it is exactly
    /// <paramref name="tagSizeInBytes"/> long, the size the adapter was created with.
    /// </summary>
    public static void RequireTagSize(ReadOnlySpan<byte> tag, int tagSizeInBytes)
    {
        if (tag.Length != tagSizeInBytes)
            throw new ArgumentException(
                $"Tag length must be {tagSizeInBytes} bytes, the size this instance was created with; got {tag.Length}.",
                nameof(tag));
    }
}
