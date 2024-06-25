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
                        bytesRead = serverStream.Read(buffer, 0, buffer.Length);
                        if (bytesRead == 0)
                        {
                            break; // 服务器关闭连接
                        }

                        // 加密目标服务器的响应
                        string dec = Encoding.ASCII.GetString(buffer);
                        Console.WriteLine("Decrypted Data: " + dec);
                        byte[] encryptedData = EncryptWithAES(buffer.Take(bytesRead).ToArray(), aesKey, aesIV);
                        
                        
                        // 将加密后的响应发送回客户端
                        clientStream.Write(encryptedData, 0, encryptedData.Length);
                    }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error in RelayData: " + ex.Message);
            }
            finally
            {
                // 确保流被正确关闭以释放资源
                clientStream.Close();
                serverStream.Close();
                Console.WriteLine("RelayData finished");
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
