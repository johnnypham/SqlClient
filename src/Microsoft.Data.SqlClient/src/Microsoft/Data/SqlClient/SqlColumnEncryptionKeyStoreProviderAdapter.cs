// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Data.Encryption.Cryptography;

namespace Microsoft.Data.SqlClient
{
    internal class SqlColumnEncryptionKeyStoreProviderAdapter : EncryptionKeyStoreProvider
    {
        private SqlColumnEncryptionKeyStoreProvider _provider;

        internal SqlColumnEncryptionKeyStoreProviderAdapter(SqlColumnEncryptionKeyStoreProvider provider)
        {
            _provider = provider;
        }

        public override string ProviderName
        {
            get { return null; }
        }

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] encryptedColumnEncryptionKey)
        {
            return _provider.DecryptColumnEncryptionKey(masterKeyPath, algorithm.ToString("F"), encryptedColumnEncryptionKey);
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] columnEncryptionKey)
        {
            return _provider.EncryptColumnEncryptionKey(masterKeyPath, algorithm.ToString("F"), columnEncryptionKey);
        }

        public override byte[] Sign(string masterKeyPath, bool allowEnclaveComputations)
        {
            return _provider.SignColumnMasterKeyMetadata(masterKeyPath, allowEnclaveComputations);
        }

        public override bool Verify(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
        {
            return _provider.VerifyColumnMasterKeyMetadata(masterKeyPath, allowEnclaveComputations, signature);
        }
    }
}
