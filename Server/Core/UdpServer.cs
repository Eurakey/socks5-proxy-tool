using System;
using System.Net;
using System.Net.Sockets;

namespace Server.Core
{
    public class UdpServer
    {
        public static void HandleUdpAssociate(NetworkStream stream, TcpClient client)
        {
            UdpClient udpClient = new UdpClient(0);
            IPEndPoint localEndPoint = (IPEndPoint)udpClient.Client.LocalEndPoint;

            byte[] response = new byte[10];
            response[0] = 0x05;
            response[1] = 0x00;
            response[2] = 0x00;
            response[3] = 0x01;
            Array.Copy(localEndPoint.Address.GetAddressBytes(), 0, response, 4, 4);
            response[8] = (byte)(localEndPoint.Port >> 8);
            response[9] = (byte)localEndPoint.Port;

            stream.Write(response, 0, response.Length);

            HandleUdpData(udpClient, client);
        }

        public static void HandleUdpData(UdpClient udpClient, TcpClient client)
        {
            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            NetworkStream clientStream = client.GetStream();

            while (true)
            {
                byte[] buffer = udpClient.Receive(ref remoteEndPoint);
                udpClient.Send(buffer, buffer.Length, remoteEndPoint);
            }
        }
    }
}