using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
// using Server.Core;

namespace Server.Core
{
    public class Socks5Server
    {
        private readonly TcpListener _listener;
        private readonly int _port;

        public Socks5Server(int port = 1080)
        {
            _port = port;
            _listener = new TcpListener(IPAddress.Any, _port);
        }

        public void Start()
        {
            _listener.Start();
            Console.WriteLine($"Socks5 server is listening on port {_port}...");

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