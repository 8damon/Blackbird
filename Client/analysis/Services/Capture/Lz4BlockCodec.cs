using System;

namespace BlackbirdInterface
{
    internal static class Lz4BlockCodec
    {
        public static byte[] Compress(byte[] input)
        {
            ArgumentNullException.ThrowIfNull(input);
            return Compress((ReadOnlySpan<byte>)input);
        }

        public static byte[] Compress(ReadOnlySpan<byte> input)
        {
            if (input.Length == 0)
            {
                return Array.Empty<byte>();
            }

            byte[] output = new byte[GetLiteralOnlyMaxCompressedSize(input.Length)];
            int written = WriteLiteralOnlyBlock(input, output);
            return output.AsSpan(0, written).ToArray();
        }

        public static byte[] Decompress(byte[] compressed, int decompressedLength)
        {
            ArgumentNullException.ThrowIfNull(compressed);
            return Decompress((ReadOnlySpan<byte>)compressed, decompressedLength);
        }

        public static byte[] Decompress(ReadOnlySpan<byte> compressed, int decompressedLength)
        {
            if (decompressedLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(decompressedLength));
            }

            if (compressed.Length == 0)
            {
                if (decompressedLength == 0)
                {
                    return Array.Empty<byte>();
                }

                throw new InvalidOperationException("Compressed LZ4 block is empty.");
            }

            byte[] output = new byte[decompressedLength];
            int src = 0;
            int dst = 0;

            while (src < compressed.Length)
            {
                byte token = compressed[src++];
                int literalLength = token >> 4;
                literalLength = ReadExtendedLength(compressed, ref src, literalLength);

                EnsureAvailable(compressed.Length - src, literalLength, "literal");
                EnsureAvailable(output.Length - dst, literalLength, "output literal");

                compressed.Slice(src, literalLength).CopyTo(output.AsSpan(dst));
                src += literalLength;
                dst += literalLength;

                if (src >= compressed.Length)
                {
                    break;
                }

                EnsureAvailable(compressed.Length - src, 2, "match offset");
                int offset = compressed[src] | (compressed[src + 1] << 8);
                src += 2;
                if (offset <= 0 || offset > dst)
                {
                    throw new InvalidOperationException("Compressed LZ4 block contains an invalid match offset.");
                }

                int matchLength = (token & 0x0F) + 4;
                matchLength = ReadExtendedLength(compressed, ref src, matchLength, includeBase: false);
                EnsureAvailable(output.Length - dst, matchLength, "output match");

                int matchSource = dst - offset;
                CopyMatch(output, matchSource, dst, matchLength);
                dst += matchLength;
            }

            if (dst != output.Length)
            {
                throw new InvalidOperationException(
                    $"Compressed LZ4 block produced {dst} bytes, expected {output.Length}.");
            }

            return output;
        }

        public static bool TryDecompress(ReadOnlySpan<byte> compressed, int decompressedLength, out byte[] output)
        {
            try
            {
                output = Decompress(compressed, decompressedLength);
                return true;
            }
            catch
            {
                output = Array.Empty<byte>();
                return false;
            }
        }

        private static int GetLiteralOnlyMaxCompressedSize(int inputLength)
        {
            int extra = inputLength / 255 + 16;
            return checked(inputLength + extra);
        }

        private static int WriteLiteralOnlyBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int dst = 0;
            int literalLength = input.Length;

            byte token = (byte)(Math.Min(15, literalLength) << 4);
            output[dst++] = token;

            if (literalLength >= 15)
            {
                int remaining = literalLength - 15;
                while (remaining >= 255)
                {
                    output[dst++] = 255;
                    remaining -= 255;
                }

                output[dst++] = (byte)remaining;
            }

            input.CopyTo(output.Slice(dst));
            dst += input.Length;
            return dst;
        }

        private static int ReadExtendedLength(ReadOnlySpan<byte> compressed, ref int src, int length,
                                              bool includeBase = true)
        {
            if (length < 15)
            {
                return length;
            }

            int total = includeBase ? length : 0;
            while (true)
            {
                if (src >= compressed.Length)
                {
                    throw new InvalidOperationException("Compressed LZ4 block is truncated.");
                }

                byte extension = compressed[src++];
                total += extension;
                if (extension != 255)
                {
                    break;
                }
            }

            return includeBase ? total : total + length;
        }

        private static void EnsureAvailable(int available, int required, string label)
        {
            if (required < 0 || available < required)
            {
                throw new InvalidOperationException($"Compressed LZ4 block is truncated while reading {label} bytes.");
            }
        }

        private static void CopyMatch(byte[] output, int sourceIndex, int destinationIndex, int length)
        {
            if (length <= 0)
            {
                return;
            }

            if (sourceIndex == destinationIndex - 1)
            {
                output.AsSpan(destinationIndex, length).Fill(output[sourceIndex]);
                return;
            }

            while (length > 0)
            {
                output[destinationIndex++] = output[sourceIndex++];
                length -= 1;
            }
        }
    }
}
