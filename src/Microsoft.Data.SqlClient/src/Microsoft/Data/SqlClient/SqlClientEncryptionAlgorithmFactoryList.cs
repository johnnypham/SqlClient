// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Data.Encryption.Cryptography;

namespace Microsoft.Data.SqlClient
{
    /// <summary>
    /// <para> Implements a global directory of all the encryption algorithms registered with client.</para>
    /// </summary>
    sealed internal class SqlClientEncryptionAlgorithmFactoryList
    {
        private readonly ConcurrentDictionary<string, SqlClientEncryptionAlgorithmFactory> _encryptionAlgoFactoryList;
        private static readonly SqlClientEncryptionAlgorithmFactoryList _singletonInstance = new SqlClientEncryptionAlgorithmFactoryList();

        private SqlClientEncryptionAlgorithmFactoryList()
        {
            _encryptionAlgoFactoryList = new ConcurrentDictionary<string, SqlClientEncryptionAlgorithmFactory>(
                concurrencyLevel: 4 * Environment.ProcessorCount, // default value in ConcurrentDictionary
                capacity: 2);

            // Add wellknown algorithm
            _encryptionAlgoFactoryList.TryAdd(SqlAeadAes256CbcHmac256Factory.AlgorithmName, new SqlAeadAes256CbcHmac256Factory());
        }

        internal static SqlClientEncryptionAlgorithmFactoryList GetInstance()
        {
            return _singletonInstance;
        }

        /// <summary>
        /// Get the registered list of algorithms as a comma separated list with algorithm names
        /// wrapped in single quotes.
        /// </summary>
        internal string GetRegisteredCipherAlgorithmNames()
        {
            StringBuilder builder = new StringBuilder();
            bool firstElem = true;
            foreach (string key in _encryptionAlgoFactoryList.Keys)
            {
                if (firstElem)
                {
                    builder.Append("'");
                    firstElem = false;
                }
                else
                {
                    builder.Append(", '");
                }
                builder.Append(key);
                builder.Append("'");
            }

            return builder.ToString();
        }

        /// <summary>
        /// Gets the algorithm handle instance for a given algorithm and instantiates it using the provided key and the encryption type.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="type"></param>
        /// <param name="algorithmName"></param>
        /// <param name="encryptionAlgorithm"></param>
        internal void GetAlgorithm(DataEncryptionKey key, byte type, string algorithmName, out AeadAes256CbcHmac256EncryptionAlgorithm encryptionAlgorithm)
        {
            if (!_encryptionAlgoFactoryList.TryGetValue(algorithmName, out SqlClientEncryptionAlgorithmFactory factory))
            {
                throw SQL.UnknownColumnEncryptionAlgorithm(algorithmName, _singletonInstance.GetRegisteredCipherAlgorithmNames());
            }

            Debug.Assert(null != factory, "Null Algorithm Factory class detected");

            // If the factory exists, following method will Create an algorithm object. If this fails,
            // it will raise an exception.
            encryptionAlgorithm = factory.GetOrCreate(key, (EncryptionType)type, algorithmName);
        }
    }
}
