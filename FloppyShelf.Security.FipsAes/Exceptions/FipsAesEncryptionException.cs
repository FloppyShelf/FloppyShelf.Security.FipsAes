using FloppyShelf.Security.FipsAes.Enums;
using System;
using System.Security.Cryptography;

namespace FloppyShelf.Security.FipsAes.Exceptions
{
    /// <summary>
    /// Custom exception class that represents errors specific to the FIPS AES encryption process.
    /// </summary>
    public sealed class FipsAesEncryptionException : CryptographicException
    {
        /// <summary>
        /// The error code associated with this exception.
        /// </summary>
        public FipsAesErrorCode ErrorCode { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FipsAesEncryptionException"/> class.
        /// </summary>
        /// <param name="errorCode">The error code representing the specific failure.</param>
        /// <param name="message">The error message.</param>
        public FipsAesEncryptionException(FipsAesErrorCode errorCode, string message)
            : base(message)
        {
            ErrorCode = errorCode;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FipsAesEncryptionException"/> class.
        /// </summary>
        /// <param name="errorCode">The error code representing the specific failure.</param>
        /// <param name="message">The error message.</param>
        /// <param name="innerException">The inner exception that caused this error.</param>
        public FipsAesEncryptionException(FipsAesErrorCode errorCode, string message, Exception innerException)
            : base(message, innerException)
        {
            ErrorCode = errorCode;
        }
    }
}
