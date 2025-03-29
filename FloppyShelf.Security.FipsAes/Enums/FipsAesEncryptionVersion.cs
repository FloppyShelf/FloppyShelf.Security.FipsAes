namespace FloppyShelf.Security.FipsAes.Enums
{
    /// <summary>
	/// Enum representing the version of the FIPS AES encryption scheme.
	/// It allows for the maximum possible version value (byte.MaxValue = 255).
	/// </summary>
	public enum FipsAesEncryptionVersion : byte
    {
        /// <summary>
        /// Version 1 of the FIPS AES encryption scheme.
        /// </summary>
        V1 = 1,
    }
}
