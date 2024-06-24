using System;
using Server;
using Server.Core;

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
}