using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Server.Utils
{
    public class Socks5Server
    {
        public static void HandleClient(TcpClient client)
        {
            NetworkStream stream = client.GetStream();
            Handshake(stream);
            Authentication(stream, client);
            HandleRequest(stream, client);
        }

        private static void Handshake(NetworkStream stream)
        {
            byte[] buffer = new byte[2];
            stream.Read(buffer, 0, 2);
            if (buffer[0] != 0x05)
            {
                throw new Exception("SOCKS版本不支持");
            }

            byte methodsCount = buffer[1];
            byte[] methods = new byte[methodsCount];
            stream.Read(methods, 0, methodsCount);

            byte[] response = { 0x05, 0x02 };
            stream.Write(response, 0, response.Length);
        }

        private static void Authentication(NetworkStream stream, TcpClient client)
        {
            byte[] authBuffer = new byte[2];
            stream.Read(authBuffer, 0, 2);
            byte version = authBuffer[0];
            byte userLen = authBuffer[1];

            byte[] userBytes = new byte[userLen];
            stream.Read(userBytes, 0, userLen);
            string username = Encoding.ASCII.GetString(userBytes);

            byte passLen = (byte)stream.ReadByte();
            byte[] passBytes = new byte[passLen];
            stream.Read(passBytes, 0, passLen);
            string password = Encoding.ASCII.GetString(passBytes);

            Console.WriteLine(username + password);

            bool isAuthSuccessful = username == "user" && password == "pass";
            Console.WriteLine("鉴权是否成功：{0}", isAuthSuccessful);


            // 包含公钥
            //更改
            var keyManager = new RSAKeyManager();
            byte[] pubKeyBytes = keyManager.GetPublicKeyBytes();  // 使用新的方法获取公钥数据
            int pubKeyLen = pubKeyBytes.Length;
            Console.WriteLine("公钥长度: {0}", pubKeyLen);
            byte[] authResponse = new byte[4 + pubKeyLen]; // 1字节VER, 1字节STATUS, 2字节LEN, 剩余为PUBKEY

            authResponse[0] = 0x01; // VER
            authResponse[1] = isAuthSuccessful ? (byte)0x00 : (byte)0x01; // STATUS (成功)
            authResponse[2] = (byte)(pubKeyLen >> 8); // LEN 高字节
            authResponse[3] = (byte)(pubKeyLen & 0xFF); // LEN 低字节

            Buffer.BlockCopy(pubKeyBytes, 0, authResponse, 4, pubKeyBytes.Length);
            Console.WriteLine(authResponse[4]);

            stream.Write(authResponse, 0, authResponse.Length);

            if (!isAuthSuccessful)
            {
                client.Close();
            }
            else
            {
                ReceiveEncryptedAESKey(stream, keyManager);
            }
        }

        private static void HandleRequest(NetworkStream stream, TcpClient client)
        {
            byte[] buffer = new byte[4];
            stream.Read(buffer, 0, 4);

            if (buffer[1] == 0x01) // Connect命令
            {
                TcpServer.HandleConnect(stream, client, buffer);
            }
            else if (buffer[1] == 0x03) // UDP Associate命令
            {
                UdpServer.HandleUdpAssociate(stream, client);
            }
        }


        private static void ReceiveEncryptedAESKey(NetworkStream stream, RSAKeyManager keyManager)
        {
            // 读取 AES 密钥长度（2 字节）
            byte[] lenBuffer = new byte[2];
            int bytesRead = stream.Read(lenBuffer, 0, 2);
            Console.WriteLine(bytesRead);
            if (bytesRead != 2)
            {
                throw new IOException("Failed to read the length of the encrypted AES key.");
            }

            // 将长度字节转换为整数
            int aesKeyLength = (lenBuffer[0] << 8) | lenBuffer[1];
            Console.WriteLine(aesKeyLength);

            // 读取加密的 AES 密钥
            byte[] encryptedAESKey = new byte[aesKeyLength];
            bytesRead = stream.Read(encryptedAESKey, 0, aesKeyLength);
            if (bytesRead != aesKeyLength)
            {
                throw new IOException("Failed to read the encrypted AES key.");
            }
            Console.WriteLine("dfa");

            // 解密 AES 密钥
            byte[] decryptedAESKey = keyManager.DecryptData(encryptedAESKey);

            // 此时，decryptedAESKey 包含解密后的 AES 密钥，可以用于后续的加密通信
            Console.WriteLine("Received and decrypted AES key: " + BitConverter.ToString(decryptedAESKey));
        }

    }

}