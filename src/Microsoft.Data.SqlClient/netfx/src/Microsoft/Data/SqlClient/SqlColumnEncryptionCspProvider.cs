﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Encryption.Cryptography;
using Microsoft.Win32;

namespace Microsoft.Data.SqlClient
{
    /// <include file='..\..\..\..\..\..\..\doc\snippets\Microsoft.Data.SqlClient\SqlColumnEncryptionCspProvider.xml' path='docs/members[@name="SqlColumnEncryptionCspProvider"]/SqlColumnEncryptionCspProvider/*' />
    public class SqlColumnEncryptionCspProvider : EncryptionKeyStoreProvider
    {
        /// <include file='..\..\..\..\..\..\..\doc\snippets\Microsoft.Data.SqlClient\SqlColumnEncryptionCspProvider.xml' path='docs/members[@name="SqlColumnEncryptionCspProvider"]/ProviderName/*' />
        public override string ProviderName { get; } = @"MSSQL_CSP_PROVIDER";

        /// <summary>
        /// RSA_OAEP is the only algorithm supported for encrypting/decrypting column encryption keys using this provider.
        /// For now, we are keeping all the providers in sync.
        /// </summary>
        private const string RSAEncryptionAlgorithmWithOAEP = @"RSA_OAEP";


        private const string HashingAlgorithm = @"SHA256";

        /// <summary>
        /// Algorithm version
        /// </summary>
        private readonly byte[] _version = new byte[] { 0x01 };


#pragma warning disable CS1572 // XML comment has a param tag, but there is no parameter by that name
        /// <include file='..\..\..\..\..\..\..\doc\snippets\Microsoft.Data.SqlClient\SqlColumnEncryptionCspProvider.xml' path='docs/members[@name="SqlColumnEncryptionCspProvider"]/DecryptColumnEncryptionKey/*' />
#pragma warning disable CS1573 // Parameter has no matching param tag in the XML comment (but other parameters do)
        public override byte[] UnwrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] encryptedColumnEncryptionKey)
#pragma warning restore CS1572 // XML comment has a param tag, but there is no parameter by that name
#pragma warning restore CS1573 // Parameter has no matching param tag in the XML comment (but other parameters do)
        {
            // Validate the input parameters
            ValidateNonEmptyCSPKeyPath(masterKeyPath, isSystemOp: true);

            if (null == encryptedColumnEncryptionKey)
            {
                throw SQL.NullEncryptedColumnEncryptionKey();
            }

            if (0 == encryptedColumnEncryptionKey.Length)
            {
                throw SQL.EmptyEncryptedColumnEncryptionKey();
            }

            // Validate encryptionAlgorithm
            ValidateEncryptionAlgorithm(algorithm, isSystemOp: true);

            // Create RSA Provider with the given CSP name and key name
            RSACryptoServiceProvider rsaProvider = CreateRSACryptoProvider(masterKeyPath, isSystemOp: true);

            // Validate whether the key is RSA one or not and then get the key size
            int keySizeInBytes = GetKeySize(rsaProvider);

            // Validate and decrypt the EncryptedColumnEncryptionKey
            // Format is 
            //           version + keyPathLength + ciphertextLength + keyPath + ciphervtext +  signature
            //
            // keyPath is present in the encrypted column encryption key for identifying the original source of the asymmetric key pair and 
            // we will not validate it against the data contained in the CMK metadata (masterKeyPath).

            // Validate the version byte
            if (encryptedColumnEncryptionKey[0] != _version[0])
            {
                throw SQL.InvalidAlgorithmVersionInEncryptedCEK(encryptedColumnEncryptionKey[0], _version[0]);
            }

            // Get key path length
            int currentIndex = _version.Length;
            UInt16 keyPathLength = BitConverter.ToUInt16(encryptedColumnEncryptionKey, currentIndex);
            currentIndex += sizeof(UInt16);

            // Get ciphertext length
            UInt16 cipherTextLength = BitConverter.ToUInt16(encryptedColumnEncryptionKey, currentIndex);
            currentIndex += sizeof(UInt16);

            // Skip KeyPath
            // KeyPath exists only for troubleshooting purposes and doesnt need validation.
            currentIndex += keyPathLength;

            // validate the ciphertext length
            if (cipherTextLength != keySizeInBytes)
            {
                throw SQL.InvalidCiphertextLengthInEncryptedCEKCsp(cipherTextLength, keySizeInBytes, masterKeyPath);
            }

            // Validate the signature length
            // Signature length should be same as the key side for RSA PKCSv1.5
            int signatureLength = encryptedColumnEncryptionKey.Length - currentIndex - cipherTextLength;
            if (signatureLength != keySizeInBytes)
            {
                throw SQL.InvalidSignatureInEncryptedCEKCsp(signatureLength, keySizeInBytes, masterKeyPath);
            }

            // Get ciphertext
            byte[] cipherText = new byte[cipherTextLength];
            Buffer.BlockCopy(encryptedColumnEncryptionKey, currentIndex, cipherText, 0, cipherText.Length);
            currentIndex += cipherTextLength;

            // Get signature
            byte[] signature = new byte[signatureLength];
            Buffer.BlockCopy(encryptedColumnEncryptionKey, currentIndex, signature, 0, signature.Length);

            // Compute the hash to validate the signature
            byte[] hash;
            using (SHA256Cng sha256 = new SHA256Cng())
            {
                sha256.TransformFinalBlock(encryptedColumnEncryptionKey, 0, encryptedColumnEncryptionKey.Length - signature.Length);
                hash = sha256.Hash;
            }

            Debug.Assert(hash != null, @"hash should not be null while decrypting encrypted column encryption key.");

            // Validate the signature
            if (!RSAVerifySignature(hash, signature, rsaProvider))
            {
                throw SQL.InvalidSignature(masterKeyPath);
            }

            // Decrypt the CEK
            return RSADecrypt(rsaProvider, cipherText);
        }


#pragma warning disable CS1572 // XML comment has a param tag, but there is no parameter by that name
        /// <include file='..\..\..\..\..\..\..\doc\snippets\Microsoft.Data.SqlClient\SqlColumnEncryptionCspProvider.xml' path='docs/members[@name="SqlColumnEncryptionCspProvider"]/EncryptColumnEncryptionKey/*' />
#pragma warning disable CS1573 // Parameter has no matching param tag in the XML comment (but other parameters do)
        public override byte[] WrapKey(string masterKeyPath, KeyEncryptionKeyAlgorithm algorithm, byte[] columnEncryptionKey)
#pragma warning restore CS1572 // XML comment has a param tag, but there is no parameter by that name
#pragma warning restore CS1573 // Parameter has no matching param tag in the XML comment (but other parameters do)
        {
            // Validate the input parameters
            ValidateNonEmptyCSPKeyPath(masterKeyPath, isSystemOp: false);

            if (null == columnEncryptionKey)
            {
                throw SQL.NullColumnEncryptionKey();
            }
            else if (0 == columnEncryptionKey.Length)
            {
                throw SQL.EmptyColumnEncryptionKey();
            }

            // Validate encryptionAlgorithm
            ValidateEncryptionAlgorithm(algorithm, isSystemOp: false);

            // Create RSA Provider with the given CSP name and key name
            RSACryptoServiceProvider rsaProvider = CreateRSACryptoProvider(masterKeyPath, isSystemOp: false);

            // Validate whether the key is RSA one or not and then get the key size
            int keySizeInBytes = GetKeySize(rsaProvider);

            // Construct the encryptedColumnEncryptionKey
            // Format is 
            //          version + keyPathLength + ciphertextLength + ciphertext + keyPath + signature
            //
            // We currently only support one version
            byte[] version = new byte[] { _version[0] };

            // Get the Unicode encoded bytes of cultureinvariant lower case masterKeyPath
            byte[] masterKeyPathBytes = Encoding.Unicode.GetBytes(masterKeyPath.ToLowerInvariant());
            byte[] keyPathLength = BitConverter.GetBytes((Int16)masterKeyPathBytes.Length);

            // Encrypt the plain text
            byte[] cipherText = RSAEncrypt(rsaProvider, columnEncryptionKey);
            byte[] cipherTextLength = BitConverter.GetBytes((Int16)cipherText.Length);
            Debug.Assert(cipherText.Length == keySizeInBytes, @"cipherText length does not match the RSA key size");

            // Compute hash
            // SHA-2-256(version + keyPathLength + ciphertextLength + keyPath + ciphertext) 
            byte[] hash;
            using (SHA256Cng sha256 = new SHA256Cng())
            {
                sha256.TransformBlock(version, 0, version.Length, version, 0);
                sha256.TransformBlock(keyPathLength, 0, keyPathLength.Length, keyPathLength, 0);
                sha256.TransformBlock(cipherTextLength, 0, cipherTextLength.Length, cipherTextLength, 0);
                sha256.TransformBlock(masterKeyPathBytes, 0, masterKeyPathBytes.Length, masterKeyPathBytes, 0);
                sha256.TransformFinalBlock(cipherText, 0, cipherText.Length);
                hash = sha256.Hash;
            }

            // Sign the hash
            byte[] signedHash = RSASignHashedData(hash, rsaProvider);
            Debug.Assert(signedHash.Length == keySizeInBytes, @"signed hash length does not match the RSA key size");
            Debug.Assert(RSAVerifySignature(hash, signedHash, rsaProvider), @"Invalid signature of the encrypted column encryption key computed.");

            // Construct the encrypted column encryption key
            // EncryptedColumnEncryptionKey = version + keyPathLength + ciphertextLength + keyPath + ciphertext +  signature
            int encryptedColumnEncryptionKeyLength = version.Length + cipherTextLength.Length + keyPathLength.Length + cipherText.Length + masterKeyPathBytes.Length + signedHash.Length;
            byte[] encryptedColumnEncryptionKey = new byte[encryptedColumnEncryptionKeyLength];

            // Copy version byte
            int currentIndex = 0;
            Buffer.BlockCopy(version, 0, encryptedColumnEncryptionKey, currentIndex, version.Length);
            currentIndex += version.Length;

            // Copy key path length
            Buffer.BlockCopy(keyPathLength, 0, encryptedColumnEncryptionKey, currentIndex, keyPathLength.Length);
            currentIndex += keyPathLength.Length;

            // Copy ciphertext length
            Buffer.BlockCopy(cipherTextLength, 0, encryptedColumnEncryptionKey, currentIndex, cipherTextLength.Length);
            currentIndex += cipherTextLength.Length;

            // Copy key path
            Buffer.BlockCopy(masterKeyPathBytes, 0, encryptedColumnEncryptionKey, currentIndex, masterKeyPathBytes.Length);
            currentIndex += masterKeyPathBytes.Length;

            // Copy ciphertext
            Buffer.BlockCopy(cipherText, 0, encryptedColumnEncryptionKey, currentIndex, cipherText.Length);
            currentIndex += cipherText.Length;

            // copy the signature
            Buffer.BlockCopy(signedHash, 0, encryptedColumnEncryptionKey, currentIndex, signedHash.Length);

            return encryptedColumnEncryptionKey;
        }

        /// <include file='..\..\..\..\..\..\..\doc\snippets\Microsoft.Data.SqlClient\SqlColumnEncryptionCspProvider.xml' path='docs/members[@name="SqlColumnEncryptionCspProvider"]/SignColumnMasterKeyMetadata/*' />
        public override byte[] Sign(string masterKeyPath, bool allowEnclaveComputations)
        {
            throw new NotSupportedException();
        }

        /// <include file='..\..\..\..\..\..\..\doc\snippets\Microsoft.Data.SqlClient\SqlColumnEncryptionCspProvider.xml' path='docs/members[@name="SqlColumnEncryptionCspProvider"]/VerifyColumnMasterKeyMetadata/*' />
        public override bool Verify(string masterKeyPath, bool allowEnclaveComputations, byte[] signature)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// This function validates that the encryption algorithm is RSA_OAEP and if it is not,
        /// then throws an exception
        /// </summary>
        /// <param name="algorithm">Asymmetric key encryptio algorithm</param>
        /// <param name="isSystemOp">Indicates if ADO.NET calls or the customer calls the API</param>
        private void ValidateEncryptionAlgorithm(KeyEncryptionKeyAlgorithm algorithm, bool isSystemOp)
        {
            if (algorithm != KeyEncryptionKeyAlgorithm.RSA_OAEP)
            {
                throw SQL.InvalidKeyEncryptionAlgorithm(algorithm.ToString(), RSAEncryptionAlgorithmWithOAEP, isSystemOp);
            }
        }


        /// <summary>
        /// Checks if the CSP key path is Empty or Null (and raises exception if they are).
        /// </summary>
        /// <param name="masterKeyPath">CSP key path.</param>
        /// <param name="isSystemOp">Indicates if ADO.NET calls or the customer calls the API</param>
        private void ValidateNonEmptyCSPKeyPath(string masterKeyPath, bool isSystemOp)
        {
            if (string.IsNullOrWhiteSpace(masterKeyPath))
            {
                if (null == masterKeyPath)
                {
                    throw SQL.NullCspKeyPath(isSystemOp);
                }
                else
                {
                    throw SQL.InvalidCspPath(masterKeyPath, isSystemOp);
                }
            }
        }

        /// <summary>
        /// Encrypt the text using specified CSP key.
        /// </summary>
        /// <param name="rscp">RSACryptoServiceProvider</param>
        /// <param name="columnEncryptionKey">Plain text Column Encryption Key.</param>
        /// <returns>Returns an encrypted blob or throws an exception if there are any errors.</returns>
        private byte[] RSAEncrypt(RSACryptoServiceProvider rscp, byte[] columnEncryptionKey)
        {
            Debug.Assert(columnEncryptionKey != null);
            Debug.Assert(rscp != null);

            return rscp.Encrypt(columnEncryptionKey, fOAEP: true);
        }

        /// <summary>
        /// Decrypt the text using specified CSP key.
        /// </summary>
        /// <param name="rscp">RSACryptoServiceProvider</param>
        /// <param name="encryptedColumnEncryptionKey">Encrypted Column Encryption Key.</param>
        /// <returns>Returns the decrypted plaintext Column Encryption Key or throws an exception if there are any errors.</returns>
        private byte[] RSADecrypt(RSACryptoServiceProvider rscp, byte[] encryptedColumnEncryptionKey)
        {
            Debug.Assert((encryptedColumnEncryptionKey != null) && (encryptedColumnEncryptionKey.Length != 0));
            Debug.Assert(rscp != null);

            return rscp.Decrypt(encryptedColumnEncryptionKey, fOAEP: true);
        }

        /// <summary>
        /// Generates signature based on RSA PKCS#v1.5 scheme using a specified CSP Key URL. 
        /// </summary>
        /// <param name="dataToSign">Text to sign.</param>
        /// <param name="rscp">RSA Provider with a given key</param>
        /// <returns>Signature</returns>
        private byte[] RSASignHashedData(byte[] dataToSign, RSACryptoServiceProvider rscp)
        {
            Debug.Assert((dataToSign != null) && (dataToSign.Length != 0));
            Debug.Assert(rscp != null);

            return rscp.SignData(dataToSign, HashingAlgorithm);
        }

        /// <summary>
        /// Verifies the given RSA PKCSv1.5 signature.
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <param name="rscp">RSA Provider with a given key</param>
        /// <returns>true if signature is valid, false if it is not valid</returns>
        private bool RSAVerifySignature(byte[] dataToVerify, byte[] signature, RSACryptoServiceProvider rscp)
        {
            Debug.Assert((dataToVerify != null) && (dataToVerify.Length != 0));
            Debug.Assert((signature != null) && (signature.Length != 0));
            Debug.Assert(rscp != null);

            return rscp.VerifyData(dataToVerify, HashingAlgorithm, signature);
        }

        /// <summary>
        /// Gets the public Key size in bytes
        /// </summary>
        /// <param name="rscp">RSA Provider with a given key</param>
        /// <returns>Key size in bytes</returns>
        private int GetKeySize(RSACryptoServiceProvider rscp)
        {
            Debug.Assert(rscp != null);

            return rscp.KeySize / 8;
        }

        /// <summary>
        /// Creates a RSACryptoServiceProvider from the given key path which contains both CSP name and key name
        /// </summary>
        /// <param name="keyPath">key path in the format of [CAPI provider name]\[key name]</param>
        /// <param name="isSystemOp">Indicates if ADO.NET calls or the customer calls the API</param>
        /// <returns></returns>
        private RSACryptoServiceProvider CreateRSACryptoProvider(string keyPath, bool isSystemOp)
        {
            // Get CNGProvider and the KeyID
            string cspProviderName;
            string keyName;
            GetCspProviderAndKeyName(keyPath, isSystemOp, out cspProviderName, out keyName);

            // Verify the existence of CSP and then get the provider type
            int providerType = GetProviderType(cspProviderName, keyPath, isSystemOp);

            // Create a new instance of CspParameters for an RSA container.
            CspParameters cspParams = new CspParameters(providerType, cspProviderName, keyName);
            cspParams.Flags = CspProviderFlags.UseExistingKey;

            RSACryptoServiceProvider rscp = null;

            try
            {
                //Create a new instance of RSACryptoServiceProvider
                rscp = new RSACryptoServiceProvider(cspParams);
            }
            catch (CryptographicException e)
            {
                const int KEYSETDOESNOTEXIST = -2146893802;
                if (e.HResult == KEYSETDOESNOTEXIST)
                {
                    // Key does not exist
                    throw SQL.InvalidCspKeyIdentifier(keyName, keyPath, isSystemOp);
                }
                else
                {
                    // bubble up the exception
                    throw;
                }
            }

            return rscp;
        }

        /// <summary>
        /// Extracts the CSP provider name and key name from the given key path
        /// </summary>
        /// <param name="keyPath">key path in the format of [CSP provider name]\[key name]</param>
        /// <param name="isSystemOp">Indicates if ADO.NET calls or the customer calls the API</param>
        /// <param name="cspProviderName">output containing the CSP provider name</param>
        /// <param name="keyIdentifier">output containing the key name</param>
        private void GetCspProviderAndKeyName(string keyPath, bool isSystemOp, out string cspProviderName, out string keyIdentifier)
        {
            int indexOfSlash = keyPath.IndexOf(@"/");
            if (indexOfSlash == -1)
            {
                throw SQL.InvalidCspPath(keyPath, isSystemOp);
            }

            cspProviderName = keyPath.Substring(0, indexOfSlash);
            keyIdentifier = keyPath.Substring(indexOfSlash + 1, keyPath.Length - (indexOfSlash + 1));

            if (cspProviderName.Length == 0)
            {
                throw SQL.EmptyCspName(keyPath, isSystemOp);
            }

            if (keyIdentifier.Length == 0)
            {
                throw SQL.EmptyCspKeyId(keyPath, isSystemOp);
            }
        }

        /// <summary>
        /// Gets the provider type from a given CAPI provider name
        /// </summary>
        /// <param name="providerName">CAPI provider name</param>
        /// <param name="keyPath">key path in the format of [CSP provider name]\[key name]</param>
        /// <param name="isSystemOp">Indicates if ADO.NET calls or the customer calls the API</param>
        /// <returns></returns>
        private int GetProviderType(string providerName, string keyPath, bool isSystemOp)
        {
            string keyName = String.Format(@"SOFTWARE\Microsoft\Cryptography\Defaults\Provider\{0}", providerName);
            RegistryKey key = Registry.LocalMachine.OpenSubKey(keyName);
            if (key == null)
            {
                throw SQL.InvalidCspName(providerName, keyPath, isSystemOp);
            }

            int providerType = (int)key.GetValue(@"Type");
            key.Close();

            return providerType;
        }
    }
}
