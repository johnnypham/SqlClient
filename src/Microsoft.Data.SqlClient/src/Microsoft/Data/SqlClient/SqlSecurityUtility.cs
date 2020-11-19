// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.Data.Encryption.Cryptography;

namespace Microsoft.Data.SqlClient
{
    internal static class SqlSecurityUtility
    {
        /// <summary>
        /// Return the algorithm name mapped to an Id.
        /// </summary>
        /// <param name="cipherAlgorithmId"></param>
        /// <param name="cipherAlgorithmName"></param>
        /// <returns></returns>
        private static string ValidateAndGetEncryptionAlgorithmName(byte cipherAlgorithmId, string cipherAlgorithmName)
        {
            if (TdsEnums.CustomCipherAlgorithmId == cipherAlgorithmId)
            {
                if (null == cipherAlgorithmName)
                {
                    throw SQL.NullColumnEncryptionAlgorithm(SqlClientEncryptionAlgorithmFactoryList.GetInstance().GetRegisteredCipherAlgorithmNames());
                }

                return cipherAlgorithmName;
            }
            else if (TdsEnums.AEAD_AES_256_CBC_HMAC_SHA256 == cipherAlgorithmId)
            {
                return SqlAeadAes256CbcHmac256Factory.AlgorithmName;
            }
            else
            {
                throw SQL.UnknownColumnEncryptionAlgorithmId(cipherAlgorithmId, GetRegisteredCipherAlgorithmIds());
            }
        }

        /// <summary>
        /// Retrieves a string with comma separated list of registered algorithm Ids (enclosed in quotes).
        /// </summary>
        private static string GetRegisteredCipherAlgorithmIds()
        {
            return @"'1', '2'";
        }

        /// <summary>
        /// Encrypts the plaintext.
        /// </summary>
        internal static byte[] EncryptWithKey(byte[] plainText, SqlCipherMetadata md, string serverName, SqlConnection connection)
        {
            Debug.Assert(serverName != null, @"serverName should not be null in EncryptWithKey.");

            // Initialize cipherAlgo if not already done.
            if (!md.IsAlgorithmInitialized())
            {
                SqlSecurityUtility.DecryptSymmetricKey(md, serverName, connection);
            }

            Debug.Assert(md.IsAlgorithmInitialized(), "Encryption Algorithm is not initialized");
            byte[] cipherText = md.CipherAlgorithm.Encrypt(plainText); // this call succeeds or throws.
            if (null == cipherText || 0 == cipherText.Length)
            {
                throw SQL.NullCipherText();
            }

            return cipherText;
        }

        /// <summary>
        /// Gets a string with first/last 10 bytes in the buff (useful for exception handling).
        /// </summary>
        internal static string GetBytesAsString(byte[] buff, bool fLast, int countOfBytes)
        {
            int count = (buff.Length > countOfBytes) ? countOfBytes : buff.Length;
            int startIndex = 0;
            if (fLast)
            {
                startIndex = buff.Length - count;
                Debug.Assert(startIndex >= 0);
            }

            return BitConverter.ToString(buff, startIndex, count);
        }

        /// <summary>
        /// Decrypts the ciphertext.
        /// </summary>
        internal static byte[] DecryptWithKey(byte[] cipherText, SqlCipherMetadata md, string serverName, SqlConnection connection)
        {
            Debug.Assert(serverName != null, @"serverName should not be null in DecryptWithKey.");

            // Initialize cipherAlgo if not already done.
            if (!md.IsAlgorithmInitialized())
            {
                SqlSecurityUtility.DecryptSymmetricKey(md, serverName, connection);
            }

            Debug.Assert(md.IsAlgorithmInitialized(), "Decryption Algorithm is not initialized");
            try
            {
                byte[] plainText = md.CipherAlgorithm.Decrypt(cipherText); // this call succeeds or throws.
                if (null == plainText)
                {
                    throw SQL.NullPlainText();
                }

                return plainText;
            }
            catch (Exception e)
            {
                // compute the strings to pass
                string keyStr = GetBytesAsString(md.EncryptionKeyInfo.Value.encryptedKey, fLast: true, countOfBytes: 10);
                string valStr = GetBytesAsString(cipherText, fLast: false, countOfBytes: 10);
                throw SQL.ThrowDecryptionFailed(keyStr, valStr, e);
            }
        }

        /// <summary>
        /// <para> Decrypts the symmetric key and saves it in metadata. In addition, initializes
        /// the SqlClientEncryptionAlgorithm for rapid decryption.</para>
        /// </summary>
        internal static void DecryptSymmetricKey(SqlCipherMetadata md, string serverName, SqlConnection connection)
        {
            Debug.Assert(md != null, "md should not be null in DecryptSymmetricKey.");
            //SqlClientSymmetricKey symKey = null;
            ProtectedDataEncryptionKey dataEncryptionKey = null;
            SqlEncryptionKeyInfo? encryptionkeyInfoChosen = null;

            DecryptSymmetricKey(md.EncryptionInfo, serverName, out dataEncryptionKey, out encryptionkeyInfoChosen, connection);
            // Given the symmetric key instantiate a SqlClientEncryptionAlgorithm object and cache it in metadata
            md.CipherAlgorithm = null;
            //SqlClientEncryptionAlgorithm cipherAlgorithm = null;
            AeadAes256CbcHmac256EncryptionAlgorithm encryptionAlgorithm = null;
            string algorithmName = ValidateAndGetEncryptionAlgorithmName(md.CipherAlgorithmId, md.CipherAlgorithmName); // may throw
            SqlClientEncryptionAlgorithmFactoryList.GetInstance().GetAlgorithm(dataEncryptionKey, md.EncryptionType, algorithmName, out encryptionAlgorithm); // will validate algorithm name and type

            Debug.Assert(encryptionAlgorithm != null);
            md.CipherAlgorithm = encryptionAlgorithm;
            md.EncryptionKeyInfo = encryptionkeyInfoChosen;
            return;
        }

        /// <summary>
        /// Decrypts the symmetric key and saves it in metadata.
        /// </summary>
        internal static void DecryptSymmetricKey(SqlTceCipherInfoEntry? sqlTceCipherInfoEntry, string serverName, out ProtectedDataEncryptionKey dataEncryptionKey, out SqlEncryptionKeyInfo? encryptionkeyInfoChosen, SqlConnection connection)
        {
            Debug.Assert(serverName != null, @"serverName should not be null in DecryptSymmetricKey.");
            Debug.Assert(sqlTceCipherInfoEntry.HasValue, "sqlTceCipherInfoEntry should not be null in DecryptSymmetricKey.");
            Debug.Assert(sqlTceCipherInfoEntry.Value.ColumnEncryptionKeyValues != null,
                "sqlTceCipherInfoEntry.ColumnEncryptionKeyValues should not be null in DecryptSymmetricKey.");

            dataEncryptionKey = null;
            encryptionkeyInfoChosen = null;
            Exception lastException = null;

            foreach (SqlEncryptionKeyInfo keyInfo in sqlTceCipherInfoEntry.Value.ColumnEncryptionKeyValues)
            {
                try
                {
                    if (GetOrCreateEncryptionKeyFromCache(keyInfo, serverName, out dataEncryptionKey, connection))
                    {
                        encryptionkeyInfoChosen = keyInfo;
                        break;
                    }
                }
                catch (Exception e)
                {
                    lastException = e;
                }
            }

            if (null == dataEncryptionKey)
            {
                Debug.Assert(null != lastException, "CEK decryption failed without raising exceptions");
                throw lastException;
            }

            Debug.Assert(encryptionkeyInfoChosen.HasValue, "encryptionkeyInfoChosen must have a value.");
        }

        /// <summary>
        /// <para> Gets or creates a key from the EncryptionKey cache.</para>
        /// </summary>
        private static bool GetOrCreateEncryptionKeyFromCache(SqlEncryptionKeyInfo keyInfo, string serverName, out ProtectedDataEncryptionKey encryptionKey, SqlConnection connection)
        {
            Debug.Assert(serverName != null, @"serverName should not be null.");
            Debug.Assert(SqlConnection.ColumnEncryptionTrustedMasterKeyPaths != null, @"SqlConnection.ColumnEncryptionTrustedMasterKeyPaths should not be null");

            EncryptionKeyStoreProvider provider = TryGetEncryptionKeyStoreProvider(serverName, keyInfo.keyPath, keyInfo.keyStoreName, connection);

            // Lookup the key in cache
            // We will simply bubble up the exception from the DecryptColumnEncryptionKey function.
            try
            {
                KeyEncryptionKey masterKey = KeyEncryptionKey.GetOrCreate($"CMK{keyInfo.cekId}", keyInfo.keyPath, provider);
                encryptionKey = ProtectedDataEncryptionKey.GetOrCreate($"CEK{keyInfo.cekId}", masterKey, keyInfo.encryptedKey);
            }
            catch (Exception e)
            {
                // Generate a new exception and throw.
                string keyHex = GetBytesAsString(keyInfo.encryptedKey, fLast: true, countOfBytes: 10);
                throw SQL.KeyDecryptionFailed(keyInfo.keyStoreName, keyHex, e);
            }

            return true;
        }

        /// <summary>
        /// Verifies Column Master Key Signature.
        /// </summary>
        internal static void VerifyColumnMasterKeySignature(string keyStoreName, string keyPath, string serverName, bool isEnclaveEnabled, byte[] CMKSignature, SqlConnection connection)
        {
            bool isValidSignature = false;
            try
            {
                Debug.Assert(SqlConnection.ColumnEncryptionTrustedMasterKeyPaths != null,
                    @"SqlConnection.ColumnEncryptionTrustedMasterKeyPaths should not be null");

                if (CMKSignature == null || CMKSignature.Length == 0)
                {
                    throw SQL.ColumnMasterKeySignatureNotFound(keyPath);
                }

                EncryptionKeyStoreProvider provider = TryGetEncryptionKeyStoreProvider(serverName, keyPath, keyStoreName, connection);

                isValidSignature = provider.Verify(keyPath, isEnclaveEnabled, CMKSignature);
            }
            catch (Exception e)
            {
                throw SQL.UnableToVerifyColumnMasterKeySignature(e);
            }

            if (!isValidSignature)
            {
                throw SQL.ColumnMasterKeySignatureVerificationFailed(keyPath);
            }
        }

        internal static EncryptionKeyStoreProvider TryGetEncryptionKeyStoreProvider(string serverName, string keyPath, string keyStoreName, SqlConnection connection)
        {
            // Check against the trusted key paths
            //
            // Get the List corresponding to the connected server
            IList<string> trustedKeyPaths;
            if (SqlConnection.ColumnEncryptionTrustedMasterKeyPaths.TryGetValue(serverName, out trustedKeyPaths))
            {
                // If the list is null or is empty or if the keyPath doesn't exist in the trusted key paths, then throw an exception.
                if ((trustedKeyPaths == null) || (trustedKeyPaths.Count() == 0) ||
                    // (trustedKeyPaths.Where(s => s.Equals(keyInfo.keyPath, StringComparison.InvariantCultureIgnoreCase)).Count() == 0)) {
                    (trustedKeyPaths.Any(
                        s => s.Equals(keyPath, StringComparison.InvariantCultureIgnoreCase)) == false))
                {
                    // throw an exception since the key path is not in the trusted key paths list for this server
                    throw SQL.UntrustedKeyPath(keyPath, serverName);
                }
            }

            // Key Not found, attempt to look up the provider
            if (!SqlConnection.TryGetEncryptionKeyStoreProvider(keyStoreName, out EncryptionKeyStoreProvider provider, connection))
            {
                throw SQL.InvalidKeyStoreProviderName(keyStoreName,
                    SqlConnection.GetColumnEncryptionSystemKeyStoreProviders(),
                    SqlConnection.GetColumnEncryptionCustomKeyStoreProviders(connection));
            }

            return provider;
        }
    }
}
