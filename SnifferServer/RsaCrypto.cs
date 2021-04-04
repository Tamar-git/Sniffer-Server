using System;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace SnifferServer
{
    /// <summary>
    /// class that is responsible for RSA cryptogtaphy
    /// </summary>
    class RsaCrypto
    {
        private RSACryptoServiceProvider ServerPrivateKey; //server's private key
        private RSACryptoServiceProvider ClientPublicKey; //client's public key
        public string ServerPublicKey; //server's public key

        /// <summary>
        /// constructor that creates an rsa object and keys
        /// </summary>
        /// <param name="publicKey">client's public key</param>
        public RsaCrypto(string publicKey)
        {
            ServerPrivateKey = new RSACryptoServiceProvider(2048);
            ServerPublicKey = ServerPrivateKey.ToXmlString(false);

            ClientPublicKey = new RSACryptoServiceProvider(2048);
            ClientPublicKey.FromXmlString(publicKey);
        }

        /// <summary>
        /// returns the original public key that the server created
        /// </summary>
        /// <returns>server's public key</returns>
        public string GetServerPublicKey()
        {
            return ServerPublicKey;
        }

        /// <summary>
        /// encryptes bytes using RSA protocol
        /// </summary>
        /// <param name="DataToEncrypt">original bytes</param>
        /// <returns>encrypted bytes</returns>
        public byte[] RSAEncrypt(byte[] DataToEncrypt)
        {
            try
            {
                byte[] encryptedData;
                //Encrypt the passed byte array and specify OAEP padding.   
                encryptedData = ClientPublicKey.Encrypt(DataToEncrypt, false);
                return encryptedData;
            }
            //Catch and display a CryptographicException   
            //to the console. 
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        /// <summary>
        /// decryptes encrypted bytes using RSA protocol
        /// </summary>
        /// <param name="DataToDecrypt">encrypted bytes</param>
        /// <returns>decrypted bytes</returns>
        public byte[] RSADecrypt(byte[] DataToDecrypt)
        {
            try
            {
                byte[] decryptedData;
                //Decrypt the passed byte array and specify OAEP padding.   
                decryptedData = ServerPrivateKey.Decrypt(DataToDecrypt, false);
                return decryptedData;
            }
            //Catch and display a CryptographicException   
            //to the console. 
            catch (CryptographicException e)
            {
                MessageBox.Show(e.ToString());

                return null;
            }
        }

    }
}