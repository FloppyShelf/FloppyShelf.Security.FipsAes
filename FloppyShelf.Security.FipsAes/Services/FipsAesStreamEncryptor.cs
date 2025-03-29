using FloppyShelf.Security.FipsAes.Enums;
using FloppyShelf.Security.FipsAes.Exceptions;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace FloppyShelf.Security.FipsAes.Services
{
    /// <summary>
    /// Class responsible for performing AES encryption and decryption using FIPS compliant algorithms.
    /// </summary>
    public sealed class FipsAesStreamEncryptor
    {
        /// <summary>
        /// A class used to hold the derived keys: AES key, HMAC key, salt, and IV.
        /// </summary>
        private sealed class DerivedKeys
        {
            public byte[] AesKey { get; set; }
            public byte[] HmacKey { get; set; } 
            public byte[] Salt { get; set; }
            public byte[] IV { get; set; }
        }

        // AES key size in bits (256 bits for AES-256)
        private const int KeySize = 256;

        // AES block size in bits (128 bits for AES)
        private const int BlockSize = 128;

        // Salt size in bytes
        private const int SaltSize = 16;

        // Number of iterations for the PBKDF2 key derivation
        private const int Iterations = 100000;

        // HMAC key size in bytes (256 bits)
        private const int HmacKeySize = 32;

        // HMAC hash length in bytes (256 bits)
        private const int HmacLength = 32;

        /// <summary>
        /// Generates a random salt of the specified length. If no salt is provided, it generates a default 16-byte salt.
        /// </summary>
        /// <param name="salt">Optional salt to use; if null or empty, a random salt is generated.</param>
        /// <returns>A byte array representing the salt.</returns>
        /// <exception cref="FipsAesEncryptionException">Thrown if the provided salt is not the correct length.</exception>
        private byte[] GenerateSalt(byte[] salt = null)
        {
            if (salt == null || salt.Length == 0)
            {
                salt = new byte[SaltSize];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt); // Fill the salt with random bytes
                }
            }
            else if (salt.Length != SaltSize)
            {
                throw new FipsAesEncryptionException(FipsAesErrorCode.InvalidSaltLength, $"Salt must be {SaltSize} bytes long.");
            }
            return salt;
        }

        /// <summary>
        /// Derives AES and HMAC keys from a password using PBKDF2 (RFC 2898) with SHA256 and a salt.
        /// </summary>
        /// <param name="password">The password used to derive the keys.</param>
        /// <param name="salt">Optional salt to use; if null, a random salt is generated.</param>
        /// <returns>A <see cref="DerivedKeys"/> object containing the derived AES key, HMAC key, salt, and IV.</returns>
        private DerivedKeys DeriveKeys(string password, byte[] salt = null)
        {
            salt = GenerateSalt(salt);

            // Derive key material using PBKDF2
            using (var kdf = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                byte[] keyMaterial = kdf.GetBytes(KeySize / 8 + HmacKeySize);

                // Split the key material into AES key and HMAC key
                byte[] aesKey = new byte[KeySize / 8];
                byte[] hmacKey = new byte[HmacKeySize];
                Buffer.BlockCopy(keyMaterial, 0, aesKey, 0, aesKey.Length);
                Buffer.BlockCopy(keyMaterial, aesKey.Length, hmacKey, 0, hmacKey.Length);

                // Zero out key material after use
                ZeroMemory(keyMaterial);

                // Generate a random IV for encryption
                byte[] iv = new byte[BlockSize / 8]; // Allocate a byte array to store the IV
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(iv); // Fill the byte array with random bytes
                }
                return new DerivedKeys()
                {
                    AesKey = aesKey,
                    HmacKey = hmacKey,
                    Salt = salt,
                    IV = iv,
                };
            }
        }

        /// <summary>
        /// Overwrites the contents of a byte array with zeroes to help securely erase sensitive data from memory.
        /// </summary>
        /// <param name="array">The byte array to be overwritten with zeroes. The array is cleared by setting all its elements to zero.</param>
        /// <remarks>
        /// This method is intended to provide a basic way to clear sensitive data from memory after use. While it uses the <see cref="Array.Clear"/> 
        /// method to overwrite the array with zeroes, it is important to note that this approach is not foolproof and might not guarantee
        /// complete security depending on the underlying platform's memory management. For example, there might be situations where
        /// the data is still present in memory before being garbage collected.
        /// </remarks>
        /// <exception cref="ArgumentNullException">Thrown when the <paramref name="array"/> parameter is <c>null</c>.</exception>
        private static void ZeroMemory(byte[] array)
        {
            // Check if the provided array is null to avoid a NullReferenceException
            if (array != null)
            {
                // Use Array.Clear to overwrite the array with zeroes
                // Array.Clear is a safer approach than manually looping through and setting each element to zero
                Array.Clear(array, 0, array.Length); // Clears the array by setting all its elements to zero
            }
            else
            {
                // It's good practice to throw an exception or log in case the array is unexpectedly null.
                // In this case, we assume the user may want to know if a null array was passed in.
                throw new ArgumentNullException(nameof(array), "The byte array cannot be null.");
            }
        }

        /// <summary>
        /// Writes the encryption header to the output stream, containing salt, IV, and version information.
        /// </summary>
        /// <param name="output">The output stream to write the header to.</param>
        /// <param name="salt">The salt used in key derivation.</param>
        /// <param name="iv">The initialization vector used for AES encryption.</param>
        /// <param name="version">The version of the encryption format (default is 1).</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>A task representing the asynchronous write operation.</returns>
        private async Task WriteHeaderAsync(Stream output, byte[] salt, byte[] iv, FipsAesEncryptionVersion version, CancellationToken cancellationToken = default)
        {
            ushort headerLength = (ushort)(salt.Length + iv.Length + 1); // Calculate the total header length
            byte[] lengthBytes = BitConverter.GetBytes(headerLength); // Convert header length to bytes
            await output.WriteAsync(lengthBytes, 0, lengthBytes.Length, cancellationToken); // Write the header length

            await output.WriteAsync(new[] { (byte)version }, 0, 1, cancellationToken); // Write version byte
            await output.WriteAsync(salt, 0, salt.Length, cancellationToken); // Write salt
            await output.WriteAsync(iv, 0, iv.Length, cancellationToken); // Write IV
        }

        /// <summary>
        /// Reads the encryption header from the input stream, containing salt, IV, and version information.
        /// </summary>
        /// <param name="input">The input stream to read the header from.</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>A tuple containing the salt, IV, and version.</returns>
        /// <exception cref="FipsAesEncryptionException">Thrown if the header is invalid or cannot be read.</exception>
        private async Task<(byte[] Salt, byte[] IV, FipsAesEncryptionVersion Version)> ReadHeaderAsync(Stream input, CancellationToken cancellationToken = default)
        {
            byte[] lengthBytes = new byte[sizeof(ushort)];
            if (await input.ReadAsync(lengthBytes, 0, lengthBytes.Length, cancellationToken) != lengthBytes.Length)
                throw new FipsAesEncryptionException(FipsAesErrorCode.HeaderReadFailed, "Failed to read header length.");

            ushort headerLength = BitConverter.ToUInt16(lengthBytes, 0);
            if (headerLength != SaltSize + BlockSize / 8 + 1)
                throw new FipsAesEncryptionException(FipsAesErrorCode.HeaderInvalidLength, "Invalid header length.");

            byte[] header = new byte[headerLength];
            int totalRead = 0;
            while (totalRead < header.Length)
            {
                int read = await input.ReadAsync(header, totalRead, header.Length - totalRead, cancellationToken);
                if (read == 0)
                    throw new FipsAesEncryptionException(FipsAesErrorCode.UnexpectedEndOfStream, "Unexpected end of stream while reading header.");
                totalRead += read;
            }

            FipsAesEncryptionVersion version = (FipsAesEncryptionVersion)header[0]; // Read the version byte
            byte[] salt = new byte[SaltSize];
            byte[] iv = new byte[BlockSize / 8];
            Buffer.BlockCopy(header, 1, salt, 0, SaltSize); // Extract the salt from the header
            Buffer.BlockCopy(header, SaltSize + 1, iv, 0, iv.Length); // Extract the IV from the header

            return (salt, iv, version); // Return the salt, IV, and version
        }

        /// <summary>
        /// Reads all bytes from the input stream asynchronously and returns them as a byte array.
        /// </summary>
        /// <param name="inputStream">The input stream to read from.</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>A byte array containing all the data read from the input stream.</returns>
        private async Task<byte[]> ReadAllBytesAsync(Stream inputStream, CancellationToken cancellationToken)
        {
            using (var ms = new MemoryStream())
            {
                byte[] buffer = new byte[8192]; // Use a buffer to read the data
                int bytesRead;
                while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                {
                    await ms.WriteAsync(buffer, 0, bytesRead, cancellationToken); // Write data to memory stream
                }
                return ms.ToArray(); // Return the byte array of the read data
            }
        }

        /// <summary>
        /// Computes an HMAC (Hashed Message Authentication Code) over the provided header and cipher data using the HMAC key.
        /// </summary>
        /// <param name="hmacKey">The HMAC key to use for the calculation.</param>
        /// <param name="header">The header to include in the HMAC calculation.</param>
        /// <param name="cipherData">The encrypted data to include in the HMAC calculation.</param>
        /// <returns>A byte array representing the computed HMAC.</returns>
        private byte[] ComputeHmac(byte[] hmacKey, byte[] header, byte[] cipherData)
        {
            // Use SHA-256 HMAC
            using (var hmac = new HMACSHA256(hmacKey))
            {
                hmac.TransformBlock(header, 0, header.Length, null, 0); // Include header in HMAC
                hmac.TransformBlock(cipherData, 0, cipherData.Length, null, 0); // Include cipher data in HMAC
                hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0); // Finalize the HMAC calculation
                return hmac.Hash; // Return the HMAC hash
            };
        }

        /// <summary>
        /// Validates that the calculated HMAC matches the stored HMAC.
        /// </summary>
        /// <param name="calculatedHmac">The calculated HMAC value.</param>
        /// <param name="storedHmac">The stored HMAC value to validate against.</param>
        /// <exception cref="FipsAesEncryptionException">Thrown if the HMACs do not match.</exception>
        private void ValidateHmac(byte[] calculatedHmac, byte[] storedHmac)
        {
            if (!FixedTimeEquals(calculatedHmac, storedHmac))
                throw new FipsAesEncryptionException(FipsAesErrorCode.HmacValidationFailed, "HMAC validation failed. Possible wrong password or data tampering.");
        }

        /// <summary>
        /// Compares two byte arrays in constant time to prevent timing attacks.
        /// This method performs a fixed-time comparison, ensuring that it takes the same amount of time
        /// regardless of whether the arrays are equal or not. This helps mitigate side-channel timing attacks.
        /// </summary>
        /// <param name="array1">The first byte array to compare.</param>
        /// <param name="array2">The second byte array to compare.</param>
        /// <returns>
        /// Returns <c>true</c> if the two byte arrays are equal, otherwise <c>false</c>.
        /// </returns>
        /// <remarks>
        /// The method uses the XOR operation to compare each byte in the arrays. It ensures that the result
        /// takes the same amount of time to execute even if the arrays differ at an early index. This avoids leaking
        /// information through timing variations.
        /// </remarks>
        public static bool FixedTimeEquals(byte[] array1, byte[] array2)
        {
            // Check if either of the arrays is null or if their lengths are not equal
            // If they are not equal in length, return false immediately
            if (array1 == null || array2 == null || array1.Length != array2.Length)
            {
                return false; // Arrays are not equal if either is null or the lengths don't match
            }

            // Initialize a result variable to 0
            // The XOR operation will accumulate differences between the two arrays
            int result = 0;

            // Iterate through each byte in the arrays
            for (int i = 0; i < array1.Length; i++)
            {
                // XOR the corresponding bytes from both arrays
                // If the bytes are the same, the XOR result will be 0; if different, it will be non-zero
                result |= array1[i] ^ array2[i];
            }

            // After iterating through all bytes, if result is 0, the arrays are equal
            // If result is non-zero, the arrays are not equal
            return result == 0;
        }


        /// <summary>
        /// Encrypts the input stream and writes the encrypted data, along with HMAC and header, to the output stream.
        /// </summary>
        /// <param name="inputStream">The input stream containing the data to encrypt.</param>
        /// <param name="outputStream">The output stream to write the encrypted data to.</param>
        /// <param name="password">The password used to derive the encryption keys.</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>A task representing the asynchronous encryption operation.</returns>
        public async Task EncryptStreamAsync(Stream inputStream, Stream outputStream, string password, CancellationToken cancellationToken)
        {
            var keys = DeriveKeys(password); // Derive keys using the provided password

            // Write the encryption header
            await WriteHeaderAsync(
                output: outputStream,
                salt: keys.Salt,
                iv: keys.IV,
                version: FipsAesEncryptionVersion.V1,
                cancellationToken: cancellationToken);

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = keys.AesKey;
                aes.IV = keys.IV;

                byte[] header = new byte[sizeof(ushort) + keys.Salt.Length + keys.IV.Length];
                Buffer.BlockCopy(BitConverter.GetBytes((ushort)(keys.Salt.Length + keys.IV.Length)), 0, header, 0, sizeof(ushort));
                Buffer.BlockCopy(keys.Salt, 0, header, sizeof(ushort), keys.Salt.Length);
                Buffer.BlockCopy(keys.IV, 0, header, sizeof(ushort) + keys.Salt.Length, keys.IV.Length);

                using (var encryptedDataStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(encryptedDataStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                        {
                            await cryptoStream.WriteAsync(buffer, 0, bytesRead, cancellationToken); // Encrypt data
                        }
                        cryptoStream.FlushFinalBlock(); // Ensure all data is written
                    }

                    byte[] cipherData = encryptedDataStream.ToArray(); // Get the encrypted data

                    byte[] hmacHash = ComputeHmac(keys.HmacKey, header, cipherData); // Calculate HMAC for integrity check

                    await outputStream.WriteAsync(cipherData, 0, cipherData.Length, cancellationToken); // Write encrypted data to output
                    await outputStream.WriteAsync(hmacHash, 0, hmacHash.Length, cancellationToken); // Write HMAC to output
                }
            }

            ZeroMemory(keys.AesKey); // Zero out the AES key
            ZeroMemory(keys.HmacKey); // Zero out the HMAC key
        }

        /// <summary>
        /// Decrypts the input stream and writes the decrypted data to the output stream.
        /// </summary>
        /// <param name="inputStream">The input stream containing the encrypted data.</param>
        /// <param name="outputStream">The output stream to write the decrypted data to.</param>
        /// <param name="password">The password used to derive the decryption keys.</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>A task representing the asynchronous decryption operation.</returns>
        public async Task DecryptStreamAsync(Stream inputStream, Stream outputStream, string password, CancellationToken cancellationToken)
        {
            var (salt, iv, version) = await ReadHeaderAsync(inputStream, cancellationToken); // Read the header from input
            var keys = DeriveKeys(password, salt); // Derive keys using the password and salt

            byte[] header = new byte[sizeof(ushort) + salt.Length + iv.Length];
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)(salt.Length + iv.Length)), 0, header, 0, sizeof(ushort));
            Buffer.BlockCopy(salt, 0, header, sizeof(ushort), salt.Length);
            Buffer.BlockCopy(iv, 0, header, sizeof(ushort) + salt.Length, iv.Length);

            byte[] encryptedData = await ReadAllBytesAsync(inputStream, cancellationToken); // Read the encrypted data
            if (encryptedData.Length < HmacLength)
                throw new FipsAesEncryptionException(FipsAesErrorCode.InvalidEncryptedDataLength, "Invalid encrypted data length.");

            byte[] cipherData = new byte[encryptedData.Length - HmacLength];
            byte[] storedHmac = new byte[HmacLength];
            Buffer.BlockCopy(encryptedData, 0, cipherData, 0, cipherData.Length); // Extract cipher data
            Buffer.BlockCopy(encryptedData, cipherData.Length, storedHmac, 0, storedHmac.Length); // Extract stored HMAC

            byte[] calculatedHmac;
            try
            {
                calculatedHmac = ComputeHmac(keys.HmacKey, header, cipherData); // Compute the expected HMAC
                ValidateHmac(calculatedHmac, storedHmac); // Validate the HMAC
            }
            catch (CryptographicException ex)
            {
                throw new FipsAesEncryptionException(FipsAesErrorCode.DecryptionFailed, "Decryption failed due to invalid HMAC.", ex);
            }

            using (var aes = Aes.Create())
            {
                aes.KeySize = KeySize;
                aes.BlockSize = BlockSize;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = keys.AesKey;
                aes.IV = iv;

                using (var cipherStream = new MemoryStream(cipherData))
                {
                    using (var cryptoStream = new CryptoStream(cipherStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        await cryptoStream.CopyToAsync(outputStream); // Decrypt and write to output stream
                    }
                }

                ZeroMemory(keys.AesKey); // Zero out the AES key
                ZeroMemory(keys.HmacKey); // Zero out the HMAC key
            }
        }

        /// <summary>
        /// Encrypts the given plaintext string and returns the encrypted data as a Base64 encoded string.
        /// </summary>
        /// <param name="plaintext">The plaintext string to encrypt.</param>
        /// <param name="password">The password used to derive the encryption keys.</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>A Base64 encoded string containing the encrypted data.</returns>
        public async Task<string> EncryptAsync(string plaintext, string password, CancellationToken cancellationToken)
        {
            using (var inputStream = new MemoryStream(Encoding.UTF8.GetBytes(plaintext)))
            using (var outputStream = new MemoryStream())
            {
                await EncryptStreamAsync(inputStream, outputStream, password, cancellationToken); // Encrypt the stream
                return Convert.ToBase64String(outputStream.ToArray()); // Return the encrypted data as a Base64 string
            }
        }

        /// <summary>
        /// Decrypts the given Base64 encoded ciphertext string and returns the decrypted plaintext as a string.
        /// </summary>
        /// <param name="ciphertext">The Base64 encoded ciphertext to decrypt.</param>
        /// <param name="password">The password used to derive the decryption keys.</param>
        /// <param name="cancellationToken">A token used to cancel the operation.</param>
        /// <returns>The decrypted plaintext string.</returns>
        public async Task<string> DecryptAsync(string ciphertext, string password, CancellationToken cancellationToken)
        {
            byte[] cipherBytes = Convert.FromBase64String(ciphertext); // Convert the Base64 string back to bytes
            using (var inputStream = new MemoryStream(cipherBytes))
            using (var outputStream = new MemoryStream())
            {
                await DecryptStreamAsync(inputStream, outputStream, password, cancellationToken); // Decrypt the stream
                return Encoding.UTF8.GetString(outputStream.ToArray()); // Return the decrypted plaintext
            }
        }
    }
}
