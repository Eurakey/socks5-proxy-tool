using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Server.Utils;

namespace Server.Core
{
    public class TcpServer
    {
        public static void HandleConnect(NetworkStream clientStream, TcpClient client, byte[] buffer, byte[] aesKey, byte[] aesIV)
        {
            string destAddress = NetworkUtils.GetDestinationAddress(clientStream, buffer[3]);
            int destPort = NetworkUtils.GetDestinationPort(clientStream);
            Console.WriteLine(destAddress, destPort);

            TcpClient destClient = new TcpClient(destAddress, destPort);
            NetworkStream serverStream = destClient.GetStream();
            
            byte[] connectResponse = CreateConnectResponse(destAddress, destPort);
            clientStream.Write(connectResponse, 0, connectResponse.Length);

            RelayData(clientStream, serverStream, aesKey, aesIV);
        }

        private static void RelayData(NetworkStream clientStream, NetworkStream serverStream, byte[] aesKey, byte[] aesIV)
        {
            byte[] buffer = new byte[8192];
            int bytesRead = 0;
            using (var aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.IV = aesIV;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                while ((bytesRead = clientStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] decryptedData = DecryptData(buffer, 0, bytesRead, decryptor);
                    serverStream.Write(decryptedData, 0, decryptedData.Length);
                    
                    bytesRead = serverStream.Read(buffer, 0, buffer.Length);
                    byte[] encryptedData = EncryptData(buffer, 0, bytesRead, encryptor);
                    clientStream.Write(encryptedData, 0, encryptedData.Length);
                }
            }
        }

        private static byte[] EncryptData(byte[] data, int offset, int count, ICryptoTransform encryptor)
        {
            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, offset, count);
                    cs.FlushFinalBlock();
                }
                return ms.ToArray();
            }
        }

        private static byte[] DecryptData(byte[] data, int offset, int count, ICryptoTransform decryptor)
        {
            using (var ms = new MemoryStream(data, offset, count))
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    byte[] decryptedData = new byte[count];
                    int bytesRead = cs.Read(decryptedData, 0, count);
                    Array.Resize(ref decryptedData, bytesRead);
                    return decryptedData;
                }
            }
        }

        private static byte[] CreateConnectResponse(string destAddress, int destPort)
        {
            byte[] response = new byte[10];
            response[0] = 0x05;
            response[1] = 0x00;
            response[2] = 0x00;
            response[3] = 0x01;

            byte[] addrBytes = IPAddress.Parse(destAddress).GetAddressBytes();
            Buffer.BlockCopy(addrBytes, 0, response, 4, addrBytes.Length);

            byte[] portBytes = BitConverter.GetBytes((ushort)destPort);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(portBytes);
            }
            Buffer.BlockCopy(portBytes, 0, response, 8, portBytes.Length);

            return response;
        }
    }
}
