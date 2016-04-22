namespace SshNet.Security.Cryptography
{
    internal class SHA1HashProvider : HashProviderBase
    {
        private const int DigestSize = 20;
        private const uint Y1 = 0x5a827999;
        private const uint Y2 = 0x6ed9eba1;
        private const uint Y3 = 0x8f1bbcdc;
        private const uint Y4 = 0xca62c1d6;

        private uint H1, H2, H3, H4, H5;

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
        /// <returns>The size, in bits, of the computed hash code.</returns>
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

            UInt32ToBigEndian(H1, output, 0);
            UInt32ToBigEndian(H2, output, 4);
            UInt32ToBigEndian(H3, output, 8);
            UInt32ToBigEndian(H4, output, 12);
            UInt32ToBigEndian(H5, output, 16);

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

            H1 = 0x67452301;
            H2 = 0xefcdab89;
            H3 = 0x98badcfe;
            H4 = 0x10325476;
            H5 = 0xc3d2e1f0;

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
            var A = H1;
            var B = H2;
            var C = H3;
            var D = H4;
            var E = H5;

            //
            // round 1
            //
            var idx = 0;

            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + F(B, C, D) + _x[idx++] + Y1;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + F(A, B, C) + _x[idx++] + Y1;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + F(E, A, B) + _x[idx++] + Y1;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + F(D, E, A) + _x[idx++] + Y1;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + F(C, D, E) + _x[idx++] + Y1;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + F(B, C, D) + _x[idx++] + Y1;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + F(A, B, C) + _x[idx++] + Y1;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + F(E, A, B) + _x[idx++] + Y1;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + F(D, E, A) + _x[idx++] + Y1;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + F(C, D, E) + _x[idx++] + Y1;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + F(B, C, D) + _x[idx++] + Y1;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + F(A, B, C) + _x[idx++] + Y1;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + F(E, A, B) + _x[idx++] + Y1;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + F(D, E, A) + _x[idx++] + Y1;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + F(C, D, E) + _x[idx++] + Y1;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + F(B, C, D) + _x[idx++] + Y1;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + F(A, B, C) + _x[idx++] + Y1;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + F(E, A, B) + _x[idx++] + Y1;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + F(D, E, A) + _x[idx++] + Y1;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + F(C, D, E) + _x[idx++] + Y1;
            C = C << 30 | (C >> 2);
            //
            // round 2
            //
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y2;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y2;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y2;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y2;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y2;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y2;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y2;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y2;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y2;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y2;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y2;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y2;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y2;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y2;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y2;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y2;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y2;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y2;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y2;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y2;
            C = C << 30 | (C >> 2);

            //
            // round 3
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + G(B, C, D) + _x[idx++] + Y3;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + G(A, B, C) + _x[idx++] + Y3;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + G(E, A, B) + _x[idx++] + Y3;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + G(D, E, A) + _x[idx++] + Y3;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + G(C, D, E) + _x[idx++] + Y3;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + G(B, C, D) + _x[idx++] + Y3;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + G(A, B, C) + _x[idx++] + Y3;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + G(E, A, B) + _x[idx++] + Y3;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + G(D, E, A) + _x[idx++] + Y3;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + G(C, D, E) + _x[idx++] + Y3;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + G(B, C, D) + _x[idx++] + Y3;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + G(A, B, C) + _x[idx++] + Y3;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + G(E, A, B) + _x[idx++] + Y3;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + G(D, E, A) + _x[idx++] + Y3;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + G(C, D, E) + _x[idx++] + Y3;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + G(B, C, D) + _x[idx++] + Y3;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + G(A, B, C) + _x[idx++] + Y3;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + G(E, A, B) + _x[idx++] + Y3;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + G(D, E, A) + _x[idx++] + Y3;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + G(C, D, E) + _x[idx++] + Y3;
            C = C << 30 | (C >> 2);

            //
            // round 4
            //
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y4;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y4;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y4;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y4;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y4;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y4;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y4;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y4;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y4;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y4;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y4;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y4;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y4;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y4;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y4;
            C = C << 30 | (C >> 2);
            // E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
            // B = rotateLeft(B, 30)
            E += (A << 5 | (A >> 27)) + H(B, C, D) + _x[idx++] + Y4;
            B = B << 30 | (B >> 2);

            D += (E << 5 | (E >> 27)) + H(A, B, C) + _x[idx++] + Y4;
            A = A << 30 | (A >> 2);

            C += (D << 5 | (D >> 27)) + H(E, A, B) + _x[idx++] + Y4;
            E = E << 30 | (E >> 2);

            B += (C << 5 | (C >> 27)) + H(D, E, A) + _x[idx++] + Y4;
            D = D << 30 | (D >> 2);

            A += (B << 5 | (B >> 27)) + H(C, D, E) + _x[idx++] + Y4;
            C = C << 30 | (C >> 2);

            H1 += A;
            H2 += B;
            H3 += C;
            H4 += D;
            H5 += E;

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
