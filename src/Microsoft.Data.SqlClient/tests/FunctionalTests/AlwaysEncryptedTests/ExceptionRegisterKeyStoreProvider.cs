// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Reflection;
using Microsoft.Data.Encryption.Cryptography;
using Xunit;

namespace Microsoft.Data.SqlClient.Tests.AlwaysEncryptedTests
{
    public class ExceptionRegisterKeyStoreProvider
    {
        private SqlConnection connection = new SqlConnection();

        [Fact]
        public void TestNullDictionary()
        {
            // Verify that we are unable to set null providers.
            string expectedMessage = "Column encryption key store provider dictionary cannot be null. Expecting a non-null value.";
            IDictionary<string, SqlColumnEncryptionKeyStoreProvider> customColumnEncryptionKeyStoreProviders = null;
            IDictionary<string, EncryptionKeyStoreProvider> customEncryptionKeyStoreProviders = null;

            ArgumentNullException e = Assert.Throws<ArgumentNullException>(() => SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customColumnEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);

            e = Assert.Throws<ArgumentNullException>(() => connection.RegisterColumnEncryptionKeyStoreProvidersOnConnection(customEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);
        }

        [Fact]
        public void TestInvalidProviderName()
        {
            // Verify the namespace reservation
            IDictionary<string, SqlColumnEncryptionKeyStoreProvider> customColumnEncryptionKeyStoreProviders = new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();
            IDictionary<string, EncryptionKeyStoreProvider> customEncryptionKeyStoreProviders = new Dictionary<string, EncryptionKeyStoreProvider>();
            customColumnEncryptionKeyStoreProviders.Add("MSSQL_DUMMY", new DummySqlColumnEncryptionKeyStoreProvider());
            customEncryptionKeyStoreProviders.Add("MSSQL_DUMMY", new DummyEncryptionKeyStoreProvider());

            string expectedMessage = "Invalid key store provider name 'MSSQL_DUMMY'. 'MSSQL_' prefix is reserved for system key store providers.";
            ArgumentException e = Assert.Throws<ArgumentException>(() => SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customColumnEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);

            e = Assert.Throws<ArgumentException>(() => connection.RegisterColumnEncryptionKeyStoreProvidersOnConnection(customEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);
        }

        [Fact]
        public void TestNullProviderValue()
        {
            // Verify null provider value are not supported
            IDictionary<string, SqlColumnEncryptionKeyStoreProvider> customColumnEncryptionKeyStoreProviders = new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();
            IDictionary<string, EncryptionKeyStoreProvider> customEncryptionKeyStoreProviders = new Dictionary<string, EncryptionKeyStoreProvider>();
            customColumnEncryptionKeyStoreProviders.Add("DUMMY", null);
            customEncryptionKeyStoreProviders.Add("DUMMY", null);

            string expectedMessage = "Null reference specified for key store provider 'DUMMY'. Expecting a non-null value.";
            ArgumentNullException e = Assert.Throws<ArgumentNullException>(() => SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customColumnEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);

            e = Assert.Throws<ArgumentNullException>(() => connection.RegisterColumnEncryptionKeyStoreProvidersOnConnection(customEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);
        }

        [Fact]
        public void TestNullProviderName()
        {
            // Verify Empty provider names are not supported.
            IDictionary<string, SqlColumnEncryptionKeyStoreProvider> customColumnEncryptionKeyStoreProviders = new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();
            IDictionary<string, EncryptionKeyStoreProvider> customEncryptionKeyStoreProviders = new Dictionary<string, EncryptionKeyStoreProvider>();
            customColumnEncryptionKeyStoreProviders.Add("   ", new DummySqlColumnEncryptionKeyStoreProvider());
            customEncryptionKeyStoreProviders.Add("   ", new DummyEncryptionKeyStoreProvider());

            string expectedMessage = "Invalid key store provider name specified. Key store provider names cannot be null or empty.";
            ArgumentNullException e = Assert.Throws<ArgumentNullException>(() => SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customColumnEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);

            e = Assert.Throws<ArgumentNullException>(() => connection.RegisterColumnEncryptionKeyStoreProvidersOnConnection(customEncryptionKeyStoreProviders));
            Assert.Contains(expectedMessage, e.Message);
        }

        [Fact]
        public void TestCanCallOnlyOnce()
        {
            // Clear out the existing providers (to ensure test-rerunability)
            Utility.ClearSqlConnectionProviders();
            // Verify the provider can be set only once.
            IDictionary<string, SqlColumnEncryptionKeyStoreProvider> customProviders = new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();
            customProviders = new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();
            customProviders.Add(new KeyValuePair<string, SqlColumnEncryptionKeyStoreProvider>(@"DummyProvider", new DummySqlColumnEncryptionKeyStoreProvider()));
            SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customProviders);
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(() => SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customProviders));
            string expectedMessage = "Key store providers cannot be set more than once.";
            Utility.ClearSqlConnectionProviders();
            Assert.Contains(expectedMessage, e.Message);
        }

        [Fact]
        public void TestPrecedenceOfGlobalCacheAndInstanceCache()
        {
            // Clear out the existing providers (to ensure test-rerunability)
            Utility.ClearSqlConnectionProviders();

            IDictionary<string, SqlColumnEncryptionKeyStoreProvider> singleColumnEncryptionKeyStoreProvider =
                new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();
            IDictionary<string, SqlColumnEncryptionKeyStoreProvider> multipleColumnEncryptionKeyStoreProviders =
                new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>();
            IDictionary<string, EncryptionKeyStoreProvider> singleEncryptionKeyStoreProvider =
                new Dictionary<string, EncryptionKeyStoreProvider>();            
            IDictionary<string, EncryptionKeyStoreProvider> multipleEncryptionKeyStoreProviders =
                new Dictionary<string, EncryptionKeyStoreProvider>();

            singleColumnEncryptionKeyStoreProvider.Add("DummyProvider1", new DummySqlColumnEncryptionKeyStoreProvider());
            multipleColumnEncryptionKeyStoreProviders.Add("DummyProvider2", new DummySqlColumnEncryptionKeyStoreProvider());
            multipleColumnEncryptionKeyStoreProviders.Add("DummyProvider3", new DummySqlColumnEncryptionKeyStoreProvider());
            singleEncryptionKeyStoreProvider.Add("DummyProvider4", new DummyEncryptionKeyStoreProvider());
            multipleEncryptionKeyStoreProviders.Add("DummyProvider5", new DummyEncryptionKeyStoreProvider());
            multipleEncryptionKeyStoreProviders.Add("DummyProvider6", new DummyEncryptionKeyStoreProvider());

            // calling this method simulates a query that requires a custom key store provider with the given name
            Assembly assembly = Assembly.GetAssembly(typeof(SqlConnection));
            Type SqlSecurityUtilityType = assembly.GetType("Microsoft.Data.SqlClient.SqlSecurityUtility");
            MethodInfo TryGetProviderMethod = SqlSecurityUtilityType.GetMethod("TryGetEncryptionKeyStoreProvider",
                BindingFlags.Static | BindingFlags.NonPublic);
            Assert.True(TryGetProviderMethod != null);

            string providerNotFoundExpectedMessage = "Invalid key store provider name: 'CustomProvider'. A key store " +
                "provider name must denote either a system key store provider or a registered custom key store provider. " +
                "Valid system key store provider names are: 'MSSQL_CERTIFICATE_STORE', 'MSSQL_CNG_STORE', " +
                "'MSSQL_CSP_PROVIDER'. Valid (currently registered) custom key store provider names are: {0}.";

            using (SqlConnection connection = new SqlConnection())
            {
                // no providers registered
                Exception e = Assert.Throws<TargetInvocationException>(
                    () => TryGetProviderMethod.Invoke(null, new object[] { "serverName", "keyPath", "CustomProvider", connection }));
                Assert.Contains(string.Format(providerNotFoundExpectedMessage, ""), e.InnerException.Message);

                // 1 provider in global cache
                SqlConnection.RegisterColumnEncryptionKeyStoreProviders(singleColumnEncryptionKeyStoreProvider);
                e = Assert.Throws<TargetInvocationException>(
                   () => TryGetProviderMethod.Invoke(null, new object[] { "serverName", "keyPath", "CustomProvider", connection }));
                Assert.Contains(string.Format(providerNotFoundExpectedMessage, "'DummyProvider1'"), e.InnerException.Message);

                Utility.ClearSqlConnectionProviders();

                // more than 1 provider in global cache
                SqlConnection.RegisterColumnEncryptionKeyStoreProviders(multipleColumnEncryptionKeyStoreProviders);
                e = Assert.Throws<TargetInvocationException>(
                   () => TryGetProviderMethod.Invoke(null, new object[] { "serverName", "keyPath", "CustomProvider", connection }));
                Assert.Contains(string.Format(providerNotFoundExpectedMessage, "'DummyProvider2', 'DummyProvider3'"),
                    e.InnerException.Message);

                // register a provider on the connection. error message should not contain the 2 providers in the global cache
                connection.RegisterColumnEncryptionKeyStoreProvidersOnConnection(singleEncryptionKeyStoreProvider);
                e = Assert.Throws<TargetInvocationException>(
                    () => TryGetProviderMethod.Invoke(null, new object[] { "serverName", "keyPath", "CustomProvider", connection }));
                Assert.Contains(string.Format(providerNotFoundExpectedMessage, "'DummyProvider4'"), e.InnerException.Message);

                // verify that instance-level providers can be set more than once and that re-registering will 
                // replace the previous collection

                // get a reference to the internal instance-level cache
                FieldInfo field = connection.GetType().GetField("_CustomEncryptionKeyStoreProviders",
                    BindingFlags.NonPublic | BindingFlags.Instance);
                Assert.True(null != field);
                ReadOnlyDictionary<string, EncryptionKeyStoreProvider> providers =
                    field.GetValue(connection) as ReadOnlyDictionary<string, EncryptionKeyStoreProvider>;

                Assert.True(providers.Count == 1);
                Assert.True(providers.ContainsKey("DummyProvider4"));

                // register a new collection
                connection.RegisterColumnEncryptionKeyStoreProvidersOnConnection(multipleEncryptionKeyStoreProviders);
                providers = field.GetValue(connection) as ReadOnlyDictionary<string, EncryptionKeyStoreProvider>;

                Assert.True(providers.Count == 2);
                Assert.True(providers.ContainsKey("DummyProvider5"));
                Assert.True(providers.ContainsKey("DummyProvider6"));
                e = Assert.Throws<TargetInvocationException>(
                    () => TryGetProviderMethod.Invoke(null, new object[] { "serverName", "keyPath", "CustomProvider", connection }));
                Assert.Contains(string.Format(providerNotFoundExpectedMessage, "'DummyProvider5', 'DummyProvider6'"),
                    e.InnerException.Message);
            }
        }
    }
}
