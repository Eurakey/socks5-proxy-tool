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

    public byte[] GetPublicKeyBytes()
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportParameters(PublicKey);
            return rsa.ExportRSAPublicKey(); // 导出ASN.1 DER编码的公钥
        }
    }

    
    public byte[] DecryptData(byte[] data)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportParameters(PrivateKey);
            return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256); 
        }
    }
}
