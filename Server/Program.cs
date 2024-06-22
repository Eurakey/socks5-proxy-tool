using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Server.Utils;

namespace Server
{
    class Program
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

                // 为每个客户端连接启动一个新的任务
                Task.Run(() => Socks5Server.HandleClient(client));
            }
        }
    }
}
