using System;

using System.Security.Cryptography;

namespace Renci.Security.Cryptography
{
    /// <summary>
    /// Provides HMAC algorithm implementation.
    /// </summary>
    public abstract class HMAC : KeyedHashAlgorithm
    {
        private HashAlgorithm _hash;
        private byte[] _innerPadding;
        private byte[] _outerPadding;

        /// <summary>
        /// Gets the size of the block.
        /// </summary>
        /// <value>
        /// The size of the block.
        /// </value>
        protected abstract int BlockSize { get; }

        /// <summary>
        /// Initializes a <see cref="HMAC"/> with the specified hash algorithm.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <exception cref="ArgumentNullException"><paramref name="hashAlgorithm"/> is <c>null</c>.</exception>
        private HMAC(HashAlgorithm hashAlgorithm)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            _hash = hashAlgorithm;
        }

        /// <summary>
        /// Initializes a <see cref="HMAC"/> with the specified hash algorithm, key and size of the computed
        /// hash code.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="key">The key.</param>
        /// <param name="hashSize">The size, in bits, of the computed hash code.</param>
        /// <exception cref="ArgumentNullException"><paramref name="hashAlgorithm"/> is <c>null</c>.</exception>
        protected HMAC(HashAlgorithm hashAlgorithm, byte[] key, int hashSize)
            : this(hashAlgorithm, key)
        {
            HashSizeValue = hashSize;
        }

        /// <summary>
        /// Initializes a <see cref="HMAC"/> with the specified hash algorithm and key.
        /// </summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="key">The key.</param>
        /// <exception cref="ArgumentNullException"><paramref name="hashAlgorithm"/> is <c>null</c>.</exception>
        protected HMAC(HashAlgorithm hashAlgorithm, byte[] key)
            : this(hashAlgorithm)
        {
            KeyValue = key;
            InternalInitialize();
        }

        /// <summary>
        /// Gets the name of the hash algorithm to use for hashing.
        /// </summary>
        public string HashName
        {
            get { return "TODO"; }
        }

        /// <summary>
        /// Gets or sets the key to use in the hash algorithm.
        /// </summary>
        /// <returns>The key to use in the hash algorithm.</returns>
        public override byte[] Key
        {
            get
            {
                return (byte[])KeyValue.Clone();
            }
            set
            {
                SetKey(value);
            }
        }

        /// <summary>
        /// Initializes an implementation of the <see cref="T:System.Security.Cryptography.HashAlgorithm" /> class.
        /// </summary>
        public override void Initialize()
        {
            InternalInitialize();
        }

        /// <summary>
        /// Hashes the core.
        /// </summary>
        /// <param name="rgb">The RGB.</param>
        /// <param name="ib">The ib.</param>
        /// <param name="cb">The cb.</param>
        protected override void HashCore(byte[] rgb, int ib, int cb)
        {
            _hash.TransformBlock(rgb, ib, cb, rgb, ib);
        }

        /// <summary>
        /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
        /// </summary>
        /// <returns>
        /// The computed hash code.
        /// </returns>
        protected override byte[] HashFinal()
        {
            // Finalize the original hash.
            _hash.TransformFinalBlock(new byte[0], 0, 0);

            var hashValue = _hash.Hash;

            // Write the outer array.
            _hash.TransformBlock(_outerPadding, 0, BlockSize, _outerPadding, 0);

            // Write the inner hash and finalize the hash.            
            _hash.TransformFinalBlock(hashValue, 0, hashValue.Length);

            var hash = _hash.Hash;
            var hashSizeBytes = HashSize/8;
            if (hash.Length == hashSizeBytes)
            {
                return hash;
            }

            var count = Math.Min(hash.Length, hashSizeBytes);
            var truncatedHash = new byte[count];
            Buffer.BlockCopy(hash, 0, truncatedHash, 0, count);
            return truncatedHash;
        }

        private void InternalInitialize()
        {
            SetKey(KeyValue);
        }

        private void SetKey(byte[] value)
        {
            _hash.Initialize();

            if (value.Length > BlockSize)
            {
                KeyValue = _hash.ComputeHash(value);
                // No need to call Initialize, ComputeHash does it automatically.
            }
            else
            {
                KeyValue = (byte[]) value.Clone();
            }

            _innerPadding = new byte[BlockSize];
            _outerPadding = new byte[BlockSize];

            // Compute inner and outer padding.
            for (var i = 0; i < KeyValue.Length; i++)
            {
                _innerPadding[i] = (byte)(0x36 ^ KeyValue[i]);
                _outerPadding[i] = (byte)(0x5C ^ KeyValue[i]);
            }
            for (var i = KeyValue.Length; i < BlockSize; i++)
            {
                _innerPadding[i] = 0x36;
                _outerPadding[i] = 0x5C;
            }

            _hash.TransformBlock(_innerPadding, 0, BlockSize, _innerPadding, 0);
        }

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged ResourceMessages.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (_hash != null)
            {
                _hash.Clear();
                _hash = null;
            }
        }
    }
}
