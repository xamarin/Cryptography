namespace SshNet.Security.Cryptography
{
    internal class SHA1HashProvider : HashProviderBase
    {
        private const int DigestSize = 20;
        private const uint Y1 = 0x5a827999;
        private const uint Y2 = 0x6ed9eba1;
        private const uint Y3 = 0x8f1bbcdc;
        private const uint Y4 = 0xca62c1d6;

        private uint _h1, _h2, _h3, _h4, _h5;

        /// <summary>
        /// The word buffer.
        /// </summary>
        private readonly uint[] _x = new uint[80];
        private int _offset;
        private readonly byte[] _buffer;
        private int _bufferOffset;
        private long _byteCount;

        /// <summary>
        /// Initializes a new instance of the <see cref="SHA1"/> class.
        /// </summary>
        public SHA1HashProvider()
        {
            _buffer = new byte[4];
            InternalInitialize();
        }

        /// <summary>
        /// Gets the size, in bits, of the computed hash code.
        /// </summary>
        /// <returns>
        /// The size, in bits, of the computed hash code.
        /// </returns>
        public override int HashSize
        {
            get
            {
                return DigestSize * 8;
            }
        }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        public override int InputBlockSize
        {
            get
            {
                return 64;
            }
        }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        public override int OutputBlockSize
        {
            get
            {
                return 64;
            }
        }

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        public override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            //  Fill the current word
            while ((_bufferOffset != 0) && (cbSize > 0))
            {
                Update(array[ibStart]);
                ibStart++;
                cbSize--;
            }

            //  Process whole words.
            while (cbSize > _buffer.Length)
            {
                ProcessWord(array, ibStart);

                ibStart += _buffer.Length;
                cbSize -= _buffer.Length;
                _byteCount += _buffer.Length;
            }

            //  Load in the remainder.
            while (cbSize > 0)
            {
                Update(array[ibStart]);

                ibStart++;
                cbSize--;
            }
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        public override byte[] HashFinal()
        {
            var output = new byte[DigestSize];
            var bitLength = (_byteCount << 3);

            //
            // add the pad bytes.
            //
            Update(128);

            while (_bufferOffset != 0)
                Update(0);

            if (_offset > 14)
            {
                ProcessBlock();
            }

            _x[14] = (uint)((ulong)bitLength >> 32);
            _x[15] = (uint)((ulong)bitLength);


            ProcessBlock();

            UInt32ToBigEndian(_h1, output, 0);
            UInt32ToBigEndian(_h2, output, 4);
            UInt32ToBigEndian(_h3, output, 8);
            UInt32ToBigEndian(_h4, output, 12);
            UInt32ToBigEndian(_h5, output, 16);

            Initialize();

            return output;
        }

        /// <summary>
        /// Initializes an implementation of the <see cref="HashProviderBase"/> class.
        /// </summary>
        public override void Initialize()
        {
            InternalInitialize();
        }

        private void InternalInitialize()
        {
            _byteCount = 0;
            _bufferOffset = 0;
            for (var i = 0; i < 4; i++)
            {
                _buffer[i] = 0;
            }

            _h1 = 0x67452301;
            _h2 = 0xefcdab89;
            _h3 = 0x98badcfe;
            _h4 = 0x10325476;
            _h5 = 0xc3d2e1f0;

            _offset = 0;
            for (var i = 0; i != _x.Length; i++)
            {
                _x[i] = 0;
            }
        }

        private void Update(byte input)
        {
            _buffer[_bufferOffset++] = input;

            if (_bufferOffset == _buffer.Length)
            {
                ProcessWord(_buffer, 0);
                _bufferOffset = 0;
            }

            _byteCount++;
        }

        private void ProcessWord(byte[] input, int inOff)
        {
            _x[_offset] = BigEndianToUInt32(input, inOff);

            if (++_offset == 16)
            {
                ProcessBlock();
            }
        }

        private static uint F(uint u, uint v, uint w)
        {
            return (u & v) | (~u & w);
        }

        private static uint H(uint u, uint v, uint w)
        {
            return u ^ v ^ w;
        }

        private static uint G(uint u, uint v, uint w)
        {
            return (u & v) | (u & w) | (v & w);
        }

        private void ProcessBlock()
        {
            //
            // expand 16 word block into 80 word block.
            //
            for (var i = 16; i < 80; i++)
            {
                var t = _x[i - 3] ^ _x[i - 8] ^ _x[i - 14] ^ _x[i - 16];
                _x[i] = t << 1 | t >> 31;
            }

            //
            // set up working variables.
            //
            var a = _h1;
            var b = _h2;
            var c = _h3;
            var d = _h4;
            var e = _h5;

            //
            // round 1
            //
            var idx = 0;

            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + F(b, c, d) + _x[idx++] + Y1;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + F(a, b, c) + _x[idx++] + Y1;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + F(e, a, b) + _x[idx++] + Y1;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + F(d, e, a) + _x[idx++] + Y1;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + F(c, d, e) + _x[idx++] + Y1;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + F(b, c, d) + _x[idx++] + Y1;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + F(a, b, c) + _x[idx++] + Y1;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + F(e, a, b) + _x[idx++] + Y1;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + F(d, e, a) + _x[idx++] + Y1;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + F(c, d, e) + _x[idx++] + Y1;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + F(b, c, d) + _x[idx++] + Y1;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + F(a, b, c) + _x[idx++] + Y1;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + F(e, a, b) + _x[idx++] + Y1;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + F(d, e, a) + _x[idx++] + Y1;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + F(c, d, e) + _x[idx++] + Y1;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + F(b, c, d) + _x[idx++] + Y1;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + F(a, b, c) + _x[idx++] + Y1;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + F(e, a, b) + _x[idx++] + Y1;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + F(d, e, a) + _x[idx++] + Y1;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + F(c, d, e) + _x[idx++] + Y1;
            c = c << 30 | (c >> 2);
            //
            // round 2
            //
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y2;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y2;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y2;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y2;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx++] + Y2;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y2;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y2;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y2;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y2;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx++] + Y2;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y2;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y2;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y2;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y2;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx++] + Y2;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y2;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y2;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y2;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y2;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx++] + Y2;
            c = c << 30 | (c >> 2);

            //
            // round 3
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + G(b, c, d) + _x[idx++] + Y3;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + G(a, b, c) + _x[idx++] + Y3;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + G(e, a, b) + _x[idx++] + Y3;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + G(d, e, a) + _x[idx++] + Y3;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + G(c, d, e) + _x[idx++] + Y3;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + G(b, c, d) + _x[idx++] + Y3;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + G(a, b, c) + _x[idx++] + Y3;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + G(e, a, b) + _x[idx++] + Y3;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + G(d, e, a) + _x[idx++] + Y3;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + G(c, d, e) + _x[idx++] + Y3;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + G(b, c, d) + _x[idx++] + Y3;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + G(a, b, c) + _x[idx++] + Y3;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + G(e, a, b) + _x[idx++] + Y3;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + G(d, e, a) + _x[idx++] + Y3;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + G(c, d, e) + _x[idx++] + Y3;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + G(b, c, d) + _x[idx++] + Y3;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + G(a, b, c) + _x[idx++] + Y3;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + G(e, a, b) + _x[idx++] + Y3;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + G(d, e, a) + _x[idx++] + Y3;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + G(c, d, e) + _x[idx++] + Y3;
            c = c << 30 | (c >> 2);

            //
            // round 4
            //
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y4;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y4;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y4;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y4;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx++] + Y4;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y4;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y4;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y4;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y4;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx++] + Y4;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y4;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y4;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y4;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y4;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx++] + Y4;
            c = c << 30 | (c >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            e += (a << 5 | (a >> 27)) + H(b, c, d) + _x[idx++] + Y4;
            b = b << 30 | (b >> 2);

            d += (e << 5 | (e >> 27)) + H(a, b, c) + _x[idx++] + Y4;
            a = a << 30 | (a >> 2);

            c += (d << 5 | (d >> 27)) + H(e, a, b) + _x[idx++] + Y4;
            e = e << 30 | (e >> 2);

            b += (c << 5 | (c >> 27)) + H(d, e, a) + _x[idx++] + Y4;
            d = d << 30 | (d >> 2);

            a += (b << 5 | (b >> 27)) + H(c, d, e) + _x[idx] + Y4;
            c = c << 30 | (c >> 2);

            _h1 += a;
            _h2 += b;
            _h3 += c;
            _h4 += d;
            _h5 += e;

            //
            // reset start of the buffer.
            //
            _offset = 0;
            for (var i = 0; i < _x.Length; i++)
            {
                _x[i] = 0;
            }
        }

        private static uint BigEndianToUInt32(byte[] bs, int off)
        {
            var n = (uint)bs[off] << 24;
            n |= (uint)bs[++off] << 16;
            n |= (uint)bs[++off] << 8;
            n |= bs[++off];

            return n;
        }

        private static void UInt32ToBigEndian(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[++off] = (byte)(n >> 16);
            bs[++off] = (byte)(n >> 8);
            bs[++off] = (byte)(n);
        }
    }
}
