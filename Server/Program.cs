using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Server
{
    class Socks5Server
    {
        static void Main(string[] args)
        {
            // 创建一个TcpListener实例，监听所有IP地址的1080端口
            TcpListener listener = new TcpListener(IPAddress.Any, 1080);
            listener.Start();
            Console.WriteLine("Socks5 server is listening on port 1080...");

            while (true)
            {
                // 接受客户端连接
                var client = listener.AcceptTcpClient();
                Console.WriteLine("Client connected!");
                HandleClient(client);
            }
        }

        static void HandleClient(TcpClient client)
        {
            NetworkStream stream = client.GetStream();

            // 处理Socks5握手
            byte[] buffer = new byte[2];
            stream.Read(buffer, 0, 2);
            if (buffer[0] != 0x05)
            {
                throw new Exception("socks版本不支持");
            }
            
            byte methodsCount = buffer[1];
            byte[] methods = new byte[methodsCount];
            stream.Read(methods, 0, methodsCount);

            // 选择身份密码认证方法
            byte[] response = { 0x05, 0x02 };
            stream.Write(response, 0, response.Length);
            
            // 处理用户名/密码验证
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

            // 简单验证用户名和密码
            if (username == "user" && password == "pass")
            {
                byte[] authResponse = { 0x01, 0x00 };
                stream.Write(authResponse, 0, authResponse.Length);
            }
            else
            {
                byte[] authResponse = { 0x01, 0x01 };
                stream.Write(authResponse, 0, authResponse.Length);
                client.Close();
                return;
            }

            // 处理Socks5请求
            buffer = new byte[4];
            stream.Read(buffer, 0, 4);
            
            if (buffer[1] == 0x01) // 判断是否为Connect命令
            {
                // 读取目标地址和端口
                byte addrType = buffer[3];
                byte[] destAddr;
                string destAddress = string.Empty;
                
                if (addrType == 0x01) // 判断是否为IPv4地址
                {
                    destAddr = new byte[4];
                    stream.Read(destAddr, 0, 4);
                    destAddress = new IPAddress(destAddr).ToString();
                }
                else if (addrType == 0x03) // 判断是否为域名
                {
                    byte addrLen = (byte)stream.ReadByte();
                    destAddr = new byte[addrLen];
                    stream.Read(destAddr, 0, addrLen);
                    destAddress = Encoding.ASCII.GetString(destAddr);
                    // Console.WriteLine(destAddress);
                }
                
                byte[] destPortBytes = new byte[2];
                stream.Read(destPortBytes, 0, 2);
                int destPort = (destPortBytes[0] << 8) | destPortBytes[1];
                // Console.WriteLine(destPort);
                
                // 连接到目标服务器
                TcpClient destClient = new TcpClient(destAddress, destPort);
                NetworkStream destStream = destClient.GetStream();
                
                // 发送成功响应
                byte[] connectResponse = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                stream.Write(connectResponse, 0, connectResponse.Length);
                
                // 在客户端和目标服务器之间转发数据
                RelayData(stream, destStream);
                
            }
        }

        static void RelayData(NetworkStream clientStream, NetworkStream serverStream)
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
