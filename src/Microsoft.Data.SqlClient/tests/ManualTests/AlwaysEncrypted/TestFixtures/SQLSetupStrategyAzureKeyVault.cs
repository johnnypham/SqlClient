// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.using System;

using System;
using System.Collections.Generic;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Data.SqlClient.AlwaysEncrypted.AzureKeyVaultProvider;
using Microsoft.Data.SqlClient.ManualTesting.Tests.AlwaysEncrypted.Setup;

namespace Microsoft.Data.SqlClient.ManualTesting.Tests.AlwaysEncrypted
{
    public class SQLSetupStrategyAzureKeyVault : SQLSetupStrategy
    {
        internal static bool isAKVProviderRegistered = false;

        public Table AKVTestTable { get; private set; }
        public SqlColumnEncryptionAzureKeyVaultProvider AkvStoreProvider;

        public SQLSetupStrategyAzureKeyVault() : base()
        {
            AkvStoreProvider = new SqlColumnEncryptionAzureKeyVaultProvider(authenticationCallback: AADUtility.AzureActiveDirectoryAuthenticationCallback);

            if (!isAKVProviderRegistered)
            {
                // this dummyprovider is required in ApiShould.TestCustomKeyStoreProviderRegistration()
                DummyEncryptionKeyStoreProvider dummyProvider = new DummyEncryptionKeyStoreProvider();

                Dictionary<string, EncryptionKeyStoreProvider> customAkvKeyStoreProviders = new Dictionary<string, EncryptionKeyStoreProvider>(capacity: 1, comparer: StringComparer.OrdinalIgnoreCase)
                {
                    {"AZURE_KEY_VAULT", AkvStoreProvider},
                    { "DummyProvider", dummyProvider}
                };

                SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customProviders: customAkvKeyStoreProviders);
                isAKVProviderRegistered = true;
            }

            SetupDatabase();
        }

        internal override void SetupDatabase()
        {
            ColumnMasterKey akvColumnMasterKey = new AkvColumnMasterKey(GenerateUniqueName("AKVCMK"), akvUrl: DataTestUtility.AKVUrl, AkvStoreProvider, DataTestUtility.EnclaveEnabled);
            databaseObjects.Add(akvColumnMasterKey);

            List<ColumnEncryptionKey> akvColumnEncryptionKeys = CreateColumnEncryptionKeys(akvColumnMasterKey, 2, AkvStoreProvider);
            databaseObjects.AddRange(akvColumnEncryptionKeys);

            List<Table> tables = CreateTables(akvColumnEncryptionKeys);
            AKVTestTable = new AKVTestTable(GenerateUniqueName("AKVTestTable"), akvColumnEncryptionKeys[0], akvColumnEncryptionKeys[1]);
            tables.Add(AKVTestTable);
            databaseObjects.AddRange(tables);

            base.SetupDatabase();
        }
    }
}
