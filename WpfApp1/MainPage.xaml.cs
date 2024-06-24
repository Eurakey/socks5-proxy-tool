using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.IO;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using WpfApp1;
using static WpfApp1.AesEncryptionFunctions;

namespace WpfApp1
{
    /// <summary>
    /// MainPage.xaml 的交互逻辑
    /// </summary>
    public partial class MainPage : Page
    {
        public MainPage()
        {
            InitializeComponent();

            Config config;
            string configPath = "config.json";

            if (!File.Exists(configPath)) // 如果配置文件不存在，创建一个新的
            {
                config = new Config
                {
                    ServerIP = "127.0.0.1",
                    ServerPort = "1080",
                    Username = "default username",
                    LocalPort = "3080"
                };
                File.WriteAllText(configPath, JsonConvert.SerializeObject(config));
            }
            else // 如果配置文件存在，读取配置文件
            {
                config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(configPath));
            }

            // 设置用户名文本框的默认值
            username.Text = config.Username;
        }

        public void register_Click(object sender, RoutedEventArgs e)
        {
            NavigationService.Navigate(new RegisterPage());
        }
        private void SaveConfig(Config config,string ConfigFilePath)
        {
            var json = JsonConvert.SerializeObject(config, Formatting.Indented);
            File.WriteAllText(ConfigFilePath, json);
        }

        public void connect_Click(object sender, RoutedEventArgs e)
        {
            string configPath = "config.json";
            Config config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(configPath));
            // 从文本框获取服务器地址、服务器端口、用户名、密码和本地端口。
            string serverAddress = config.ServerIP;
            int serverPort = int.Parse(config.ServerPort);
            string userName = username.Text;
            string password = password_input.Text;
            int localPort = int.Parse(config.LocalPort);

            config.Username = username.Text;
            SaveConfig(config, configPath);

            // 在一个新的线程中启动 SOCKS5 客户端。
            Task.Run(() => StartSocks5Client(serverAddress, serverPort, userName, password, localPort));
        }

        private void StartSocks5Client(string serverAddress, int serverPort, string userName, string password, int localPort)
        {
            byte[] aesKey;
            byte[] aesIV;
            try
            {
                Log("Starting SOCKS5 client...");

                using (TcpClient client = new TcpClient(serverAddress, serverPort))
                using (NetworkStream stream = client.GetStream())
                {
                    Log("Connected to server");

                    // 握手：socks版本5，支持2种认证：无认证和用户名密码
                    byte[] handshakeRequest = new byte[] { 0x05, 0x02, 0x00, 0x02 };
                    stream.Write(handshakeRequest, 0, handshakeRequest.Length);

                    //接收：socks版本5，要求用户名和密码
                    byte[] handshakeResponse = new byte[2];
                    stream.Read(handshakeResponse, 0, handshakeResponse.Length);

                    if (handshakeResponse[1] == 0x02)
                    {
                        Log("Server selected username/password authentication");

                        //编码字节数组
                        byte[] userNameBytes = Encoding.ASCII.GetBytes(userName);
                        byte[] passwordBytes = Encoding.ASCII.GetBytes(password);


                        byte[] authRequest = new byte[3 + userNameBytes.Length + passwordBytes.Length];
                        authRequest[0] = 0x01;//子协议版本1
                        authRequest[1] = (byte)userNameBytes.Length;//用户名字节长度

                        Array.Copy(userNameBytes, 0, authRequest, 2, userNameBytes.Length);//复制用户名
                        authRequest[2 + userNameBytes.Length] = (byte)passwordBytes.Length;//密码字节长度
                        Array.Copy(passwordBytes, 0, authRequest, 3 + userNameBytes.Length, passwordBytes.Length);//复制密码

                        stream.Write(authRequest, 0, authRequest.Length);

                        byte[] authResponse = new byte[4];
                        stream.Read(authResponse, 0, authResponse.Length);

                        if (authResponse[1] != 0x00)
                        {
                            Log("Authentication failed");
                            MessageBox.Show("Authentication failed");
                            return;
                        }
                        else if(authResponse[1] == 0x00)
                        {
                            Log("Authentication successfully");
                        }

                        //读RSA公钥长度
                        int publicKeyLength = (authResponse[2] << 8) + authResponse[3];
                        Log("PubKey Length:", publicKeyLength);

                        // 读RSA公钥
                        byte[] publicKeyBytes = new byte[publicKeyLength];
                        int bytesRead = 0;
                        while (bytesRead < publicKeyLength)
                        {
                            int result = stream.Read(publicKeyBytes, bytesRead, publicKeyLength - bytesRead);
                            if (result == 0)
                            {
                                throw new Exception("Connection closed unexpectedly.");
                            }
                            bytesRead += result;
                        }
                        RSA rsa = RSA.Create();
                        rsa.ImportRSAPublicKey(publicKeyBytes, out _);

                        Log("Public key received successfully");

                        // 生成AES密钥
                        
                        using (Aes aes = Aes.Create())
                        {
                            aes.GenerateKey();
                            aes.GenerateIV();
                            aesKey = aes.Key;
                            aesIV = aes.IV;

                            // 加密AES密钥
                            byte[] encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
                            byte[] encryptedAesIV = rsa.Encrypt(aesIV, RSAEncryptionPadding.OaepSHA256);

                            // Send encrypted AES key
                            byte[] keyLength = BitConverter.GetBytes((short)encryptedAesKey.Length);
                            Array.Reverse(keyLength);  // Always send length in big endian
                            Log("keyLength[0]", keyLength[0]);
                            Log("keyLength[1]", keyLength[1]);
                            stream.Write(keyLength, 0, keyLength.Length);
                            stream.Write(encryptedAesKey, 0, encryptedAesKey.Length);
                            stream.Write(encryptedAesIV, 0, encryptedAesIV.Length);
                        }

                        Log("AES key exchange successful");

                    }
                    else
                    {
                        Log("Server did not select username/password authentication");
                        MessageBox.Show("Server did not select username/password authentication");
                        return;
                    }
                    string destination_ip = "103.235.46.96";
                    ushort destination_port = 80;
                    // Connect Request
                    byte[] destinationAddress = ParseIpAddress(destination_ip); // Use the TextBox for the destination IP
                    ushort destinationPort = destination_port; // Use the TextBox for the destination port

                    byte[] connectRequest = new byte[10];
                    connectRequest[0] = 0x05; // SOCKS version
                    connectRequest[1] = 0x01; // CONNECT command
                    connectRequest[2] = 0x00; // Reserved
                    connectRequest[3] = 0x01; // Address type (IPv4)
                    Array.Copy(destinationAddress, 0, connectRequest, 4, destinationAddress.Length);
                    connectRequest[8] = (byte)(destinationPort >> 8);
                    connectRequest[9] = (byte)destinationPort;

                    stream.Write(connectRequest, 0, connectRequest.Length);

                    byte[] connectResponse = new byte[10];
                    stream.Read(connectResponse, 0, connectResponse.Length);

                    if (connectResponse[1] != 0x00)
                    {
                        Log("Connection request failed");
                        MessageBox.Show("Connection failed");
                        return;
                    }

                    Log("Connection request successful");
                    // 通过代理服务器与目标服务器通信
                    string httpRequest = "GET / HTTP/1.1\r\nHost: baidu.com\r\nConnection: close\r\n\r\n";
                    byte[] httpRequestBytes = Encoding.ASCII.GetBytes(httpRequest);
                    // 加密 HTTP 请求
                    byte[] encryptedHttpRequestBytes = EncryptWithAES(httpRequestBytes, aesKey, aesIV);

                    // 发送加密后的请求
                    stream.Write(encryptedHttpRequestBytes, 0, encryptedHttpRequestBytes.Length);

                    stream.Write(httpRequestBytes, 0, httpRequestBytes.Length);
                    // 读取响应并显示
                    byte[] buffer = new byte[8192];
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        int bytesRead;
                        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            memoryStream.Write(buffer, 0, bytesRead);
                        }

                        byte[] encryptedResponseBytes = memoryStream.ToArray();
                        byte[] decryptedResponseBytes = DecryptWithAES(encryptedResponseBytes, aesKey, aesIV);

                        string responseString = Encoding.ASCII.GetString(decryptedResponseBytes);

                        // 将解密后的响应写入文件
                        File.WriteAllText("response.html", responseString);
                    }

                    /*// Start TcpListener to listen on local port
                    TcpListener listener = new TcpListener(IPAddress.Loopback, localPort);
                    listener.Start();
                    Log("Listening on port " + localPort);*/

                    /*while (true)
                    {
                        TcpClient localClient = listener.AcceptTcpClient();
                        Task.Run(() => HandleClient(localClient, client));
                    }*/
                }
            }
            catch (Exception ex)
            {
                Log("Error: " + ex.Message);
                MessageBox.Show("Error: " + ex.Message);
            }
        }

        private byte[] ParseIpAddress(string ipAddress)
        {
            string[] parts = ipAddress.Split('.');
            if (parts.Length != 4)
            {
                throw new ArgumentException("Invalid IP address format");
            }

            byte[] addressBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                addressBytes[i] = byte.Parse(parts[i]);
            }
            return addressBytes;
        }


        private void HandleClient(TcpClient localClient, TcpClient serverClient)
        {
            using (NetworkStream localStream = localClient.GetStream())
            using (NetworkStream serverStream = serverClient.GetStream())
            {
                Task.Run(() => RelayData(localStream, serverStream));
                Task.Run(() => RelayData(serverStream, localStream));
            }
        }

        private void RelayData(NetworkStream input, NetworkStream output)
        {
            byte[] buffer = new byte[8192];
            int bytesRead;
            try
            {
                while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, bytesRead);
                    output.Flush();
                }
            }
            catch (Exception)
            {
                // Handle exceptions as needed
            }
        }

        public void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                logBox.Text += message + Environment.NewLine;
                logBox.ScrollToEnd(); // Auto scroll to end
            });
        }
        //调试版本Log
        public void Log(string message, object variable = null)
        {
            Dispatcher.Invoke(() =>
            {
                string logMessage = message;
                if (variable != null)
                {
                    logMessage += ": " + variable.ToString();
                }
                logBox.Text += logMessage + Environment.NewLine;
                logBox.ScrollToEnd(); // Auto scroll to end
            });
        }

        

        static void SendEncryptedData(NetworkStream stream, byte[] encryptedData)
        {
            byte[] dataLength = BitConverter.GetBytes((short)encryptedData.Length);
            Array.Reverse(dataLength);  // Always send length in big endian
            stream.Write(dataLength, 0, dataLength.Length);
            stream.Write(encryptedData, 0, encryptedData.Length);
        }
    }   
}
