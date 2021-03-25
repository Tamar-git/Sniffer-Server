using System;
using System.Security.Cryptography;
using System.Text;

namespace SnifferServer
{
    class RsaCrypto
    {
        public static string _privateKey;
        public static string _publicKey;
        public static string _serverPublicKey;
        private static UnicodeEncoding _encoder = new UnicodeEncoding();

        private RSACryptoServiceProvider ServerPrivateKey; //server's private key
        private RSACryptoServiceProvider ClientPublicKey; //client's public key
        public string ServerPublicKey; //server's public key

        /// <summary>
        /// constructor that creates an rsa object and keys
        /// </summary>
        /// <param name="publicKey"></param>
        public RsaCrypto(string publicKey)
        {
            ServerPrivateKey = new RSACryptoServiceProvider(2048);
            ServerPublicKey = ServerPrivateKey.ToXmlString(false);
            //var rsa = new RSACryptoServiceProvider();
            ClientPublicKey = new RSACryptoServiceProvider();
            ClientPublicKey.FromXmlString(publicKey);
            //_publicKey = publicKey;
            //_privateKey = rsa.ToXmlString(true);
            //_serverPublicKey = rsa.ToXmlString(false);
        }

        /// <summary>
        /// gets an encrypted string, decrypts and returns the readable data
        /// </summary>
        /// <param name="data">encrypted data</param>
        /// <returns>original data</returns>
        public string Decrypt(string data)
        {
            var dataArray = data.ToCharArray();
            byte[] dataByte = _encoder.GetBytes(dataArray, 0, dataArray.Length);

            var decryptedByte = ServerPrivateKey.Decrypt(dataByte, false);
            return _encoder.GetString(decryptedByte);

            //var rsa = new RSACryptoServiceProvider();
            //var dataArray = data.Split(new char[] { ',' });
            //byte[] dataByte = new byte[dataArray.Length];
            //for (int i = 0; i < dataArray.Length; i++)
            //{
            //    dataByte[i] = Convert.ToByte(dataArray[i]);
            //}

            //rsa.FromXmlString(_privateKey);
            //var decryptedByte = rsa.Decrypt(dataByte, false);
            //return _encoder.GetString(decryptedByte);
        }

        /// <summary>
        ///  gets an a string and returns it encrypted (using rsa)
        /// </summary>
        /// <param name="data">original data</param>
        /// <returns>encrypted data</returns>
        public string Encrypt(string data)
        {
            var dataArray = data.ToCharArray();
            byte[] dataByte = Convert.FromBase64CharArray(dataArray, 0, dataArray.Length);
            var encryptedByte = ClientPublicKey.Encrypt(dataByte, false);
            return _encoder.GetString(encryptedByte);
            //var rsa = new RSACryptoServiceProvider();
            //rsa.FromXmlString(_publicKey);
            //var dataToEncrypt = _encoder.GetBytes(data);
            //var encryptedByteArray = rsa.Encrypt(dataToEncrypt, false);
            //var length = encryptedByteArray.Length;
            //var item = 0;
            //var sb = new StringBuilder();
            //foreach (var x in encryptedByteArray)
            //{
            //    item++;
            //    sb.Append(x);

            //    if (item < length)
            //        sb.Append(",");
            //}

            //return sb.ToString();
        }

       
        /// <summary>
        /// returns the original public key that the server created
        /// </summary>
        /// <returns></returns>
        public string GetServerPublicKey()
        {
            return ServerPublicKey;
        }
    }
}