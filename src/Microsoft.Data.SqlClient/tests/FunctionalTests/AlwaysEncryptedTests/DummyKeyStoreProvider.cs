// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using Microsoft.Data.Encryption.Cryptography;

namespace Microsoft.Data.SqlClient.Tests.AlwaysEncryptedTests
{
    /// <summary>
    /// Dummy Key Store Provider that inherits SqlColumnEncryptionKeyStoreProvider
    /// </summary>
    internal class DummySqlColumnEncryptionKeyStoreProvider : SqlColumnEncryptionKeyStoreProvider
    {
        public override byte[] DecryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// Dummy Key Store Provider that inherits EncryptionKeyStoreProvider
    /// </summary>
    internal class DummyEncryptionKeyStoreProvider : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "DummyProvider";

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] columnEncryptionKey)
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
    /// Dummy Key Store Provider that inherits EncryptionKeyStoreProvider and has a reserved name
    /// </summary>
    internal class DummyEncryptionKeyStoreProviderWithReservedName : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "MSSQL_DUMMY";

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] columnEncryptionKey)
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
    /// Dummy Key Store Provider that inherits EncryptionKeyStoreProvider and has a reserved name with mixed casing
    /// </summary>
    internal class DummyEncryptionKeyStoreProviderWithReservedNameMixedCase : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "MsSqL_DUMMY";

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] columnEncryptionKey)
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
    /// Dummy Key Store Provider that inherits EncryptionKeyStoreProvider and has an empty name
    /// </summary>
    internal class DummyEncryptionKeyStoreProviderWithEmptyName : EncryptionKeyStoreProvider
    {
        public override string ProviderName => "";

        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] columnEncryptionKey)
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
