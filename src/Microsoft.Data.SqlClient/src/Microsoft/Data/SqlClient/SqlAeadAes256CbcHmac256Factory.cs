// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Microsoft.Data.Encryption.Cryptography;

namespace Microsoft.Data.SqlClient
{
    /// <summary>
    /// This is a factory class for AEAD_AES_256_CBC_HMAC_SHA256
    /// </summary>
    internal class SqlAeadAes256CbcHmac256Factory : SqlClientEncryptionAlgorithmFactory
    {
        /// <summary>
        /// Algorithm Name
        /// </summary>
        internal const string AlgorithmName = @"AEAD_AES_256_CBC_HMAC_SHA256";

        /// <summary>
        /// Creates an instance of AeadAes256CbcHmac256Algorithm class with a given key
        /// </summary>
        /// <param name="encryptionKey">Root key</param>
        /// <param name="encryptionType">Encryption Type. Expected values are either Deterministic or Randomized.</param>
        /// <param name="algorithmName">Encryption Algorithm.</param>
        /// <returns></returns>
        internal override AeadAes256CbcHmac256EncryptionAlgorithm GetOrCreate(DataEncryptionKey encryptionKey, EncryptionType encryptionType, string algorithmName)
        {
            // Callers should have validated the encryption algorithm and the encryption key
            Debug.Assert(encryptionKey != null);
            Debug.Assert(string.Equals(algorithmName, AlgorithmName, StringComparison.OrdinalIgnoreCase) == true);

            // Validate encryption type
            if (!((encryptionType == EncryptionType.Deterministic) || (encryptionType == EncryptionType.Randomized)))
            {
                throw SQL.InvalidEncryptionType(AlgorithmName,
                                                encryptionType,
                                              EncryptionType.Deterministic,
                                              EncryptionType.Randomized);
            }

            return AeadAes256CbcHmac256EncryptionAlgorithm.GetOrCreate(encryptionKey, encryptionType);
        }
    }
}
