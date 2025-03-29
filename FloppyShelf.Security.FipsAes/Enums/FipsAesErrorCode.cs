namespace FloppyShelf.Security.FipsAes.Enums
{
    /// <summary>
    /// Enum representing error codes related to AES encryption/decryption operations.
    /// </summary>
    public enum FipsAesErrorCode : byte
    {
        InvalidSaltLength,
        HeaderReadFailed,
        HeaderInvalidLength,
        UnexpectedEndOfStream,
        InvalidEncryptedDataLength,
        HmacValidationFailed,
        DecryptionFailed,
        GeneralCryptoError
    }
}
