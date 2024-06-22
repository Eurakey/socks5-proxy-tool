using System;
using System.IO;
using System.Security.Cryptography;

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
            PublicKey = rsa.ExportParameters(false); // 仅导出公钥参数
            PrivateKey = rsa.ExportParameters(true); // 导出公私钥参数

            // 保存密钥到文件
            File.WriteAllText(publicKeyPath, rsa.ToXmlString(false)); // 公钥
            File.WriteAllText(privateKeyPath, rsa.ToXmlString(true)); // 私钥
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

    /*public byte[] GetAsnEncodedPublicKey()
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(PublicKey);
            return rsa.ExportRSAPublicKey();  // 导出ASN.1 DER编码的公钥
        }
    }*/


    /*public byte[] GetPublicKeyBytes()
    {
        // 获取公钥参数
        byte[] modulus = PublicKey.Modulus;
        byte[] exponent = PublicKey.Exponent;

        // 组合公钥字节数组
        byte[] pubKeyBytes = new byte[modulus.Length + exponent.Length + 8]; // 4字节用于模数长度，4字节用于指数长度

        Buffer.BlockCopy(BitConverter.GetBytes(modulus.Length), 0, pubKeyBytes, 0, 4);
        Buffer.BlockCopy(modulus, 0, pubKeyBytes, 4, modulus.Length);
        Buffer.BlockCopy(BitConverter.GetBytes(exponent.Length), 0, pubKeyBytes, 4 + modulus.Length, 4);
        Buffer.BlockCopy(exponent, 0, pubKeyBytes, 8 + modulus.Length, exponent.Length);

        return pubKeyBytes;
    }*/
    public byte[] GetPublicKeyBytes()
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(PublicKey);
            return rsa.ExportRSAPublicKey();  // 导出ASN.1 DER编码的公钥
        }
    }


    public byte[] DecryptData(byte[] data)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(PrivateKey);
            return rsa.Decrypt(data, true);
        }
    }
}
