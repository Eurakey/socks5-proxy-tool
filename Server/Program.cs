using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Server.Core;
using Server.Utils;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {
            var server = new Socks5Server();
            server.Start();
        }
    }

    public class Socks5Server
    {
        private readonly TcpListener _listener;

        public Socks5Server()
        {
            _listener = new TcpListener(IPAddress.Any, 1080);
        }

        public void Start()
        {
            _listener.Start();
            Console.WriteLine("Socks5 server is listening on port 1080...");

            while (true)
            {
                var client = _listener.AcceptTcpClient();
                Console.WriteLine("Client connected!");
                Task.Run(() => HandleClient(client));
            }
        }

        private static void HandleClient(TcpClient client)
        {
            var handler = new ClientHandler(client);
            handler.Process();
        }
    }
}