using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Server.Utils;
using static Utils.AesEncryption;

namespace Server.Core
{
    public class TcpServer
    {
        public static void HandleConnect(NetworkStream clientStream, TcpClient client, byte[] buffer, byte[] aesKey, byte[] aesIV)
        {
            Console.WriteLine(BitConverter.ToString(buffer));

            string destAddress;
            int destPort;
            int addressType = buffer[3];

            if (addressType == 0x03) // Domain name
            {
                int domainLength = clientStream.ReadByte();
                byte[] domainBytes = new byte[domainLength];
                clientStream.Read(domainBytes, 0, domainLength);
                string domainName = Encoding.ASCII.GetString(domainBytes);
                destPort = NetworkUtils.GetDestinationPort(clientStream);

                // Resolve domain name to IP address
                destAddress = Dns.GetHostAddresses(domainName).FirstOrDefault()?.ToString();
                if (destAddress == null)
                {
                    throw new Exception($"Failed to resolve domain: {domainName}");
                }
                Console.WriteLine($"Domain: {domainName}, IP: {destAddress}, Port: {destPort}");
            }
            else // IPv4 or other
            {
                destAddress = NetworkUtils.GetDestinationAddress(clientStream, (byte)addressType);
                destPort = NetworkUtils.GetDestinationPort(clientStream);
                Console.WriteLine($"{destAddress}:{destPort}");
            }

            TcpClient destClient = new TcpClient(destAddress, destPort);
            NetworkStream serverStream = destClient.GetStream();
            
            byte[] connectResponse = CreateConnectResponse(destAddress, destPort, addressType);
            clientStream.Write(connectResponse, 0, connectResponse.Length);

            RelayData(clientStream, serverStream, aesKey, aesIV);
        }

       private static void RelayData(NetworkStream clientStream, NetworkStream serverStream, byte[] aesKey, byte[] aesIV)
        {
            byte[] buffer = new byte[8192];
            int bytesRead = 0;

            try
            {
                Console.WriteLine("RelayData started");

                while ((bytesRead = clientStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    // 解密从客户端收到的数据
                    byte[] decryptedData = DecryptWithAES(buffer.Take(bytesRead).ToArray(), aesKey, aesIV);
                    string decryptedString = Encoding.ASCII.GetString(decryptedData);
                    Console.WriteLine("Decrypted Data: " + decryptedString);

                    // 将解密后的数据发送到目标服务器
                    serverStream.Write(decryptedData, 0, decryptedData.Length);

                    // 从目标服务器读取响应
                    MemoryStream responseStream = new MemoryStream();
                    while ((bytesRead = serverStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        responseStream.Write(buffer, 0, bytesRead);
                    }

                    // 加密目标服务器的响应
                    byte[] responseData = responseStream.ToArray();
                    byte[] encryptedData = EncryptWithAES(responseData, aesKey, aesIV);

                    // 计算加密数据的长度，并转换为三字节形式
                    int encryptedDataLength = encryptedData.Length;
                    byte[] lengthBytes = new byte[3];
                    lengthBytes[0] = (byte)((encryptedDataLength >> 16) & 0xFF);
                    lengthBytes[1] = (byte)((encryptedDataLength >> 8) & 0xFF);
                    lengthBytes[2] = (byte)(encryptedDataLength & 0xFF);

                    // 先将长度信息发送到客户端
                    clientStream.Write(lengthBytes, 0, lengthBytes.Length);

                    // 再将加密后的响应发送回客户端
                    clientStream.Write(encryptedData, 0, encryptedData.Length);

                    // 记录解密后的响应（用于调试）
                    string decryptedResponseString = Encoding.ASCII.GetString(responseData);
                    Console.WriteLine("Decrypted Response Data: " + decryptedResponseString);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception in RelayData: " + ex.Message);
            }
        }

        private static byte[] CreateConnectResponse(string destAddress, int destPort, int addressType)
        {
            byte[] response;
            if (addressType == 0x03) // Domain name
            {
                response = new byte[10 + destAddress.Length];
                response[0] = 0x05;
                response[1] = 0x00;
                response[2] = 0x00;
                response[3] = 0x03;
                response[4] = (byte)destAddress.Length;

                byte[] addrBytes = Encoding.ASCII.GetBytes(destAddress);
                Buffer.BlockCopy(addrBytes, 0, response, 5, addrBytes.Length);

                byte[] portBytes = BitConverter.GetBytes((ushort)destPort);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(portBytes);
                }
                Buffer.BlockCopy(portBytes, 0, response, 5 + addrBytes.Length, portBytes.Length);
            }
            else // IPv4 or IPv6
            {
                response = new byte[10];
                response[0] = 0x05;
                response[1] = 0x00;
                response[2] = 0x00;
                response[3] = (byte)addressType;

                byte[] addrBytes = IPAddress.Parse(destAddress).GetAddressBytes();
                Buffer.BlockCopy(addrBytes, 0, response, 4, addrBytes.Length);

                byte[] portBytes = BitConverter.GetBytes((ushort)destPort);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(portBytes);
                }
                Buffer.BlockCopy(portBytes, 0, response, 8, portBytes.Length);
            }

            return response;
        }
    }
}
