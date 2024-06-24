using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Server.Utils
{
    public static class NetworkUtils
    {
        public static string GetDestinationAddress(NetworkStream stream, byte addrType)
        {
            byte[] destAddr;
            if (addrType == 0x01)
            {
                destAddr = new byte[4];
                stream.Read(destAddr, 0, 4);
                return new IPAddress(destAddr).ToString();
            }
            else if (addrType == 0x03)
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
    }
}