// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Data.Encryption.Cryptography;

namespace Microsoft.Data.SqlClient.ManualTesting.Tests.AlwaysEncrypted.Setup
{
    /// <summary>
    /// Dummy Key Store Provider that inherits EncryptionKeyStoreProvider
    /// </summary>
    internal class DummyEncryptionKeyStoreProvider : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "DummyProvider";

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] Sign(string masterKeyPath, bool allowEnclaveComputations)
        {
            throw new NotImplementedException();
        }

        public override bool Verify(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Dummy Key Store Provider 2 that inherits EncryptionKeyStoreProvider
    /// </summary>
    internal class DummyEncryptionKeyStoreProvider2 : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "DummyProvider2";

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] Sign(string masterKeyPath, bool allowEnclaveComputations)
        {
            throw new NotImplementedException();
        }

        public override bool Verify(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
        {
            throw new NotImplementedException();
        }
    }
}
