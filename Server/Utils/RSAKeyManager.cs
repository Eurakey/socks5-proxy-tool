using System;
using System.IO;
using System.Security.Cryptography;

namespace Server.Utils
{
    public class RSAKeyManager
    {
        private readonly string publicKeyPath = "publicKey.xml";
        private readonly string privateKeyPath = "privateKey.xml";

        public RSAParameters PublicKey { get; private set; }
        public RSAParameters PrivateKey { get; private set; }

        public RSAKeyManager()
        {
            if (File.Exists(publicKeyPath) && File.Exists(privateKeyPath))
            {
                LoadKeysFromFile();
            }
            else
            {
                GenerateAndSaveKeys();
            }
        }

        private void GenerateAndSaveKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                PublicKey = rsa.ExportParameters(false);
                PrivateKey = rsa.ExportParameters(true);

                // Save keys to file
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
                File.WriteAllText(privateKeyPath, rsa.ToXmlString(true));
            }
        }

        private void LoadKeysFromFile()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                PublicKey = rsa.ExportParameters(false);

                rsa.FromXmlString(File.ReadAllText(privateKeyPath));
                PrivateKey = rsa.ExportParameters(true);
            }
        }

        public byte[] GetPublicKeyBytes()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(PublicKey);

                // 手动构造公钥字节数组
                byte[] modulus = PublicKey.Modulus;
                byte[] exponent = PublicKey.Exponent;
                byte[] pubKeyBytes = new byte[modulus.Length + exponent.Length + 8]; // 4 bytes for modulus length and 4 bytes for exponent length

                Buffer.BlockCopy(BitConverter.GetBytes(modulus.Length), 0, pubKeyBytes, 0, 4);
                Buffer.BlockCopy(modulus, 0, pubKeyBytes, 4, modulus.Length);
                Buffer.BlockCopy(BitConverter.GetBytes(exponent.Length), 0, pubKeyBytes, 4 + modulus.Length, 4);
                Buffer.BlockCopy(exponent, 0, pubKeyBytes, 8 + modulus.Length, exponent.Length);

                return pubKeyBytes;
            }
        }
    }
}