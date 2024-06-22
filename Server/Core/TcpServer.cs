using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Server.Utils;

namespace Server.Core
{
    public class TcpServer
    {
        public static void HandleConnect(NetworkStream stream, TcpClient client, byte[] buffer)
        {
            string destAddress = NetworkUtils.GetDestinationAddress(stream, buffer[3]);
            int destPort = NetworkUtils.GetDestinationPort(stream);
            Console.WriteLine(destAddress, destPort);

            TcpClient destClient = new TcpClient(destAddress, destPort);
            NetworkStream destStream = destClient.GetStream();
            
            byte[] connectResponse = CreateConnectResponse(destAddress, destPort);
            stream.Write(connectResponse, 0, connectResponse.Length);

            RelayData(stream, destStream);
        }

        private static void RelayData(NetworkStream clientStream, NetworkStream serverStream)
        {
            byte[] buffer = new byte[8192];
            int bytesRead = 0;
            while ((bytesRead = clientStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                serverStream.Write(buffer, 0, bytesRead);
                bytesRead = serverStream.Read(buffer, 0, buffer.Length);
                clientStream.Write(buffer, 0, bytesRead);
                Console.WriteLine(bytesRead);
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
