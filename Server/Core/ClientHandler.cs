using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using Server.Utils;

namespace Server.Core
{
    public class ClientHandler
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;

        public ClientHandler(TcpClient client)
        {
            _client = client;
            _stream = client.GetStream();
        }

        public void Process()
        {
            Handshake();
            Authentication();
            HandleRequest();
        }

        private void Handshake()
        {
            byte[] buffer = new byte[2];
            _stream.Read(buffer, 0, 2);
            if (buffer[0] != 0x05)
            {
                throw new Exception("SOCKS版本不支持");
            }

            byte methodsCount = buffer[1];
            byte[] methods = new byte[methodsCount];
            _stream.Read(methods, 0, methodsCount);

            byte[] response = { 0x05, 0x02 };
            _stream.Write(response, 0, response.Length);
        }

        private void Authentication()
        {
            byte[] authBuffer = new byte[2];
            _stream.Read(authBuffer, 0, 2);
            byte version = authBuffer[0];
            byte userLen = authBuffer[1];

            byte[] userBytes = new byte[userLen];
            _stream.Read(userBytes, 0, userLen);
            string username = Encoding.ASCII.GetString(userBytes);

            byte passLen = (byte)_stream.ReadByte();
            byte[] passBytes = new byte[passLen];
            _stream.Read(passBytes, 0, passLen);
            string password = Encoding.ASCII.GetString(passBytes);

            Console.WriteLine(username + password);

            bool isAuthSuccessful = username == "user" && password == "pass";
            Console.WriteLine("鉴权是否成功：{0}", isAuthSuccessful);

            var keyManager = new RSAKeyManager();
            byte[] pubKeyBytes = keyManager.GetPublicKeyBytes();
            int pubKeyLen = pubKeyBytes.Length;
            Console.WriteLine("公钥长度: {0}", pubKeyLen);
            byte[] authResponse = new byte[4 + pubKeyLen];

            authResponse[0] = 0x01;
            authResponse[1] = isAuthSuccessful ? (byte)0x00 : (byte)0x01;
            authResponse[2] = (byte)(pubKeyLen >> 8);
            authResponse[3] = (byte)(pubKeyLen & 0xFF);

            Buffer.BlockCopy(pubKeyBytes, 0, authResponse, 4, pubKeyBytes.Length);
            Console.WriteLine(authResponse[4]);

            _stream.Write(authResponse, 0, authResponse.Length);

            if (!isAuthSuccessful)
            {
                _client.Close();
            }
            else
            {
                ReceiveEncryptedAESKey(keyManager);
            }
        }

        private void HandleRequest()
        {
            byte[] buffer = new byte[4];
            _stream.Read(buffer, 0, 4);

            if (buffer[1] == 0x01)
            {
                TcpServer.HandleConnect(_stream, _client, buffer);
            }
            else if (buffer[1] == 0x03)
            {
                UdpServer.HandleUdpAssociate(_stream, _client);
            }
        }

        private void ReceiveEncryptedAESKey(RSAKeyManager keyManager)
        {
            byte[] lenBuffer = new byte[2];
            int bytesRead = _stream.Read(lenBuffer, 0, 2);
            Console.WriteLine(bytesRead);
            if (bytesRead != 2)
            {
                throw new IOException("Failed to read the length of the encrypted AES key.");
            }

            int aesKeyLength = (lenBuffer[0] << 8) | lenBuffer[1];
            Console.WriteLine(aesKeyLength);

            byte[] encryptedAESKey = new byte[aesKeyLength];
            bytesRead = _stream.Read(encryptedAESKey, 0, aesKeyLength);
            if (bytesRead != aesKeyLength)
            {
                throw new IOException("Failed to read the encrypted AES key.");
            }

            byte[] decryptedAESKey = keyManager.DecryptData(encryptedAESKey);
            Console.WriteLine("Received and decrypted AES key: " + BitConverter.ToString(decryptedAESKey));
        }
    }
}
