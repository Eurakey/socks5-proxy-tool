using System;
using Server;
using Server.Core;
using NLog;
using NLog.Config;
using NLog.Targets;

namespace Server
{
    class Program
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        static void Main(string[] args)
        {
            ConfigureLogging();
            Logger.Info("Starting Socks5 server...");
            var server = new Socks5Server();
            server.Start();
        }

        private static void ConfigureLogging()
        {
            var config = new LoggingConfiguration();
            
            // Console target
            var logconsole = new ConsoleTarget("logconsole");
            config.AddTarget(logconsole);
            config.AddRule(LogLevel.Info, LogLevel.Fatal, logconsole);
            
            // File target
            var logfile = new FileTarget("logfile") { FileName = "file.txt" };
            config.AddTarget(logfile);
            config.AddRule(LogLevel.Info, LogLevel.Fatal, logfile);
            
            LogManager.Configuration = config;
        }
    }
}