using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Newtonsoft.Json;
using static Utils.AesEncryption;

namespace WpfApp1
{
    public partial class MainPage : Page
    {
        private TcpClient _client;
        private NetworkStream _stream;
        private CancellationTokenSource _cancellationTokenSource;
        private bool _isConnected;

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
        
        private void SaveConfig(Config config, string configFilePath)
        {
            var json = JsonConvert.SerializeObject(config, Formatting.Indented);
            File.WriteAllText(configFilePath, json);
        }

        public void connect_Click(object sender, RoutedEventArgs e)
        {
            if (_isConnected)
            {
                // 断开连接
                _cancellationTokenSource?.Cancel();
                _stream?.Close();
                _client?.Close();
                _isConnected = false;
                Log("Disconnected from server.");
                connect.Content = "连接";
            }
            else
            {
            string configPath = "config.json";
            Config config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(configPath));
            // 从文本框获取服务器地址、服务器端口、用户名、密码和本地端口。
            string serverAddress = config.ServerIP;
            int serverPort = int.Parse(config.ServerPort);
            string userName = username.Text;
            string password = password_input.Text;
            if(password.Length<=0)
            {
                    Log("Password Empty.Check and try again.");
                    return;
            }
            int localPort = int.Parse(config.LocalPort);

            config.Username = username.Text;
            SaveConfig(config, configPath);

            _cancellationTokenSource = new CancellationTokenSource();
                Task.Run(() => StartSocks5Client(serverAddress, serverPort, userName, password, localPort, _cancellationTokenSource.Token));
                _isConnected = true;
                connect.Content = "断开"; // 更新按钮文本
            }
        }

        private void StartSocks5Client(string serverAddress, int serverPort, string userName, string password, int localPort, CancellationToken cancellationToken)
        {
            byte[] aesKey;
            byte[] aesIV;
            try
            {
                Log("Starting SOCKS5 client...");

                using (_client = new TcpClient(serverAddress, serverPort))
                using (_stream = _client.GetStream())
                {
                    Log("Connected to server");

                    // 握手：socks版本5，支持2种认证：无认证和用户名密码
                    byte[] handshakeRequest = new byte[] { 0x05, 0x02, 0x00, 0x02 };
                    _stream.Write(handshakeRequest, 0, handshakeRequest.Length);

                    // 接收：socks版本5，要求用户名和密码
                    byte[] handshakeResponse = new byte[2];
                    _stream.Read(handshakeResponse, 0, handshakeResponse.Length);

                    if (handshakeResponse[1] == 0x02)
                    {
                        Log("Server selected username/password authentication");

                        // 编码字节数组
                        byte[] userNameBytes = Encoding.ASCII.GetBytes(userName);
                        byte[] passwordBytes = Encoding.ASCII.GetBytes(password);

                        byte[] authRequest = new byte[3 + userNameBytes.Length + passwordBytes.Length];
                        authRequest[0] = 0x01; // 子协议版本1
                        authRequest[1] = (byte)userNameBytes.Length; // 用户名字节长度

                        Array.Copy(userNameBytes, 0, authRequest, 2, userNameBytes.Length); // 复制用户名
                        authRequest[2 + userNameBytes.Length] = (byte)passwordBytes.Length; // 密码字节长度
                        Array.Copy(passwordBytes, 0, authRequest, 3 + userNameBytes.Length, passwordBytes.Length); // 复制密码

                        _stream.Write(authRequest, 0, authRequest.Length);

                        byte[] authResponse = new byte[4];
                        _stream.Read(authResponse, 0, authResponse.Length);

                        if (authResponse[1] != 0x00)
                        {
                            Log("Authentication failed");
                            MessageBox.Show("Authentication failed");
                            return;
                        }
                        else if (authResponse[1] == 0x00)
                        {
                            Log("Authentication successfully");
                        }

                        // 读RSA公钥长度
                        int publicKeyLength = (authResponse[2] << 8) + authResponse[3];
                        Log("PubKey Length:", publicKeyLength);

                        // 读RSA公钥
                        byte[] publicKeyBytes = new byte[publicKeyLength];
                        int bytesRead = 0;
                        while (bytesRead < publicKeyLength)
                        {
                            int result = _stream.Read(publicKeyBytes, bytesRead, publicKeyLength - bytesRead);
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
                            Log("aesIV", aesIV.Length);

                            // 加密AES密钥
                            byte[] encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
                            byte[] keyLength = BitConverter.GetBytes((short)encryptedAesKey.Length);
                            Array.Reverse(keyLength); // Always send length in big endian
                            Log("keyLength[0]", keyLength[0]);
                            Log("keyLength[1]", keyLength[1]);
                            _stream.Write(keyLength, 0, keyLength.Length);
                            _stream.Write(encryptedAesKey, 0, encryptedAesKey.Length);
                            _stream.Write(aesIV, 0, aesIV.Length);
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

                    _stream.Write(connectRequest, 0, connectRequest.Length);

                    byte[] connectResponse = new byte[10];
                    _stream.Read(connectResponse, 0, connectResponse.Length);

                    if (connectResponse[1] != 0x00)
                    {
                        Log("Connection request failed");
                        MessageBox.Show("Connection failed");
                        return;
                    }

                    Log("Connection request successful");

                    string httpRequest = "GET / HTTP/1.1\r\nHost: baidu.com\r\nConnection: close\r\n\r\n";
                    byte[] httpRequestBytes = Encoding.ASCII.GetBytes(httpRequest);
                    byte[] encryptedHttpRequestBytes = EncryptWithAES(httpRequestBytes, aesKey, aesIV);

                    _stream.Write(encryptedHttpRequestBytes, 0, encryptedHttpRequestBytes.Length);
                    Log("Request sent successfully");

                    // 读取2字节长度并转换为大端序int
                    byte[] lengthBytes = new byte[3];
                    _stream.Read(lengthBytes, 0, lengthBytes.Length);
                    Log("HTMLlength",lengthBytes.Length);

                    // 如果系统的字节顺序不是大端序，反转字节数组
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(lengthBytes);
                    }

                    // 将字节数组转换为int
                    int length = BitConverter.ToInt16(lengthBytes, 0);

                    // 更新buffer长度
                    byte[] buffer = new byte[length];
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        int bytesRead;
                        try
                        {
                            while ((bytesRead = _stream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                if (cancellationToken.IsCancellationRequested)
                                {
                                    Log("Disconnection requested, stopping read operation.");
                                    break;
                                }

                                memoryStream.Write(buffer, 0, bytesRead);
                                Log($"Read {bytesRead} bytes from stream.");

                                byte[] encryptedData = memoryStream.ToArray();
                                byte[] decryptedData = DecryptWithAES(encryptedData.Take(bytesRead).ToArray(), aesKey, aesIV);

                                string decryptedString = Encoding.ASCII.GetString(decryptedData);
                                Log("Decrypted Data: " + decryptedString);
                                if (string.IsNullOrEmpty(decryptedString))
                                {
                                    Log("Decrypted response is empty.");
                                }
                                else
                                {
                                    File.WriteAllText("response.txt", decryptedString);
                                    Log("Response written to response.html");
                                }
                            }
                        }
                        catch (IOException e)
                        {
                            if (!cancellationToken.IsCancellationRequested)
                            {
                                Log($"IOException: {e.Message}");
                            }
                            else
                            {
                                Log("Operation canceled.");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    Log("Error: " + ex.Message);
                    MessageBox.Show("Error: " + ex.Message);
                }
                else
                {
                    Log("Operation canceled.");
                }
            }
            finally
            {
                _isConnected = false;
                Application.Current.Dispatcher.Invoke(() => connect.Content = "连接"); // 确保在主线程上更新按钮文本
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
                logBox.ScrollToEnd(); 
            });
        }

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
            Array.Reverse(dataLength); // Always send length in big endian
            stream.Write(dataLength, 0, dataLength.Length);
            stream.Write(encryptedData, 0, encryptedData.Length);
        }
    }
}
