using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Server.Utils
{
    public class TcpServer
    {
        public static void HandleConnect(NetworkStream stream, TcpClient client, byte[] buffer)
        {
            string destAddress = GetDestinationAddress(stream, buffer[3]);
            int destPort = GetDestinationPort(stream);

            TcpClient destClient = new TcpClient(destAddress, destPort);
            NetworkStream destStream = destClient.GetStream();

            byte[] connectResponse = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
            stream.Write(connectResponse, 0, connectResponse.Length);

            RelayData(stream, destStream);
        }

        public static string GetDestinationAddress(NetworkStream stream, byte addrType)
        {
            byte[] destAddr;
            if (addrType == 0x01) // IPv4
            {
                destAddr = new byte[4];
                stream.Read(destAddr, 0, 4);
                return new IPAddress(destAddr).ToString();
            }
            else if (addrType == 0x03) // 域名
            {
                byte addrLen = (byte)stream.ReadByte();
                destAddr = new byte[addrLen];
                stream.Read(destAddr, 0, addrLen);
                return Encoding.ASCII.GetString(destAddr);
            }

            throw new Exception("未知的地址类型");
        }

        public static int GetDestinationPort(NetworkStream stream)
        {
            byte[] destPortBytes = new byte[2];
            stream.Read(destPortBytes, 0, 2);
            return (destPortBytes[0] << 8) | destPortBytes[1];
        }
        
        private static void RelayData(NetworkStream clientStream, NetworkStream serverStream)
        {
            // 简化的数据转发逻辑
            // 后续完善
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = clientStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                serverStream.Write(buffer, 0, bytesRead);
                bytesRead = serverStream.Read(buffer, 0, buffer.Length);
                clientStream.Write(buffer, 0, bytesRead);
            }
        }
    }
}