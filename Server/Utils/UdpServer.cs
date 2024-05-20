using System;
using System.Net;
using System.Net.Sockets;

namespace Server.Utils
{
    public class UdpServer
    {
        public static void HandleUdpAssociate(NetworkStream stream, TcpClient client)
        {
            // 绑定UDP端口
            UdpClient udpClient = new UdpClient(0); // 使用系统分配的端口
            IPEndPoint localEndPoint = (IPEndPoint)udpClient.Client.LocalEndPoint;

            // 发送UDP关联响应
            byte[] response = new byte[10];
            response[0] = 0x05; // SOCKS版本
            response[1] = 0x00; // 成功
            response[2] = 0x00; // 保留
            response[3] = 0x01; // 地址类型（IPv4）
            Array.Copy(localEndPoint.Address.GetAddressBytes(), 0, response, 4, 4); // 绑定的IP地址
            response[8] = (byte)(localEndPoint.Port >> 8); // 绑定的端口（高字节）
            response[9] = (byte)localEndPoint.Port; // 绑定的端口（低字节）

            stream.Write(response, 0, response.Length);

            // 处理UDP数据
            HandleUdpData(udpClient, client);
        }

        public static void HandleUdpData(UdpClient udpClient, TcpClient client)
        {
            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            NetworkStream clientStream = client.GetStream();

            while (true)
            {
                byte[] buffer = udpClient.Receive(ref remoteEndPoint);
                // 解析UDP数据包并转发
                // 这里可以添加详细的UDP数据处理逻辑
                udpClient.Send(buffer, buffer.Length, remoteEndPoint);
            }
        }
    }
}