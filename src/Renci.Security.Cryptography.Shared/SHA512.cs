using System.Security.Cryptography;

namespace Renci.Security.Cryptography
{
    /// <summary>
    /// Computes the SHA512 hash for input data. 
    /// </summary>
    public class SHA512 : HashAlgorithm
    {
        private IHashProvider _hashProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="SHA512"/> class.
        /// </summary>
        public SHA512()
        {
            _hashProvider = new SHA512HashProvider();
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
                return _hashProvider.HashSize;
            }
        }

        /// <summary>
        /// Gets the input block size.
        /// </summary>
        /// <returns>
        /// The input block size.
        /// </returns>
        public
#if !NETFX_CORE
        override
#endif
        int InputBlockSize
        {
            get
            {
                return _hashProvider.InputBlockSize;
            }
        }

        /// <summary>
        /// Gets the output block size.
        /// </summary>
        /// <returns>
        /// The output block size.
        /// </returns>
        public
#if !NETFX_CORE
        override
#endif
        int OutputBlockSize
        {
            get
            {
                return _hashProvider.OutputBlockSize;

            }
        }

#if !NETFX_CORE
        /// <summary>
        /// Gets a value indicating whether the current transform can be reused.
        /// </summary>
        /// <returns>
        /// Always true.
        /// </returns>
        public override bool CanReuseTransform
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Gets a value indicating whether multiple blocks can be transformed.
        /// </summary>
        /// <returns>
        /// true if multiple blocks can be transformed; otherwise, false.
        /// </returns>
        public override bool CanTransformMultipleBlocks
        {
            get
            {
                return true;
            }
        }
#endif // !NETFX_CORE

        /// <summary>
        /// Routes data written to the object into the hash algorithm for computing the hash.
        /// </summary>
        /// <param name="array">The input to compute the hash code for.</param>
        /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
        /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            _hashProvider.HashCore(array, ibStart, cbSize);
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        protected override byte[] HashFinal()
        {
            return _hashProvider.HashFinal();
        }

        /// <summary>
        /// Initializes an implementation of the <see cref="HashAlgorithm"/> class.
        /// </summary>
        public override void Initialize()
        {
            _hashProvider.Initialize();
        }

        /// <summary>
        /// Releases the unmanaged resources used by the <see cref="SHA512"/> and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                _hashProvider.Dispose();
                _hashProvider = null;
            }
        }
    }
}
