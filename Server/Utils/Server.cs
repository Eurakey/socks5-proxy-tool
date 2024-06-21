using System;
using System.Net;
using System.Net.Sockets;
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
            byte[] authResponse;

            
            // 包含公钥
            var keyManager = new RSAKeyManager();
            byte[] pubKeyBytes = keyManager.GetPublicKeyBytes();
            byte pubKeyLen = (byte)pubKeyBytes.Length;
            authResponse = new byte[3 + pubKeyLen]; // 1字节VER, 1字节STATUS, 1字节LEN, 剩余为PUBKEY

            authResponse[0] = 0x01; // VER
            authResponse[1] = isAuthSuccessful ? (byte)0x00 : (byte)0x01; // STATUS (成功)
            authResponse[3] = pubKeyLen;

            Buffer.BlockCopy(pubKeyBytes, 0, authResponse, 3, pubKeyBytes.Length);
            

            stream.Write(authResponse, 0, authResponse.Length);

            if (!isAuthSuccessful)
            {
                client.Close();
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
        
    }

}