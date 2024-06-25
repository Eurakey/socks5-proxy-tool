using System;
using System.Data;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite; // 使用 Microsoft.Data.Sqlite
using Server.Utils;
using static Utils.AesEncryption;

namespace Server.Core
{
    public class ClientHandler
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly RSAKeyManager _keyManager;
        private byte[] _aesKey;
        private byte[] _aesIV;

        // SQLite 数据库连接字符串
        private readonly string _connectionString = "Data Source=users.db";

        public ClientHandler(TcpClient client)
        {
            _client = client;
            _stream = client.GetStream();
            _keyManager = new RSAKeyManager();
            InitializeDatabase(); // 确保数据库在类实例化时初始化
        }

        public void Process()
        {
            Handshake();
            Authentication();
            HandleRequest();
        }

        private void Handshake()
        {
            byte[] buffer = new byte[2];
            _stream.Read(buffer, 0, 2);
            if (buffer[0] != 0x05)
            {
                throw new Exception("SOCKS版本不支持");
            }

            byte methodsCount = buffer[1];
            byte[] methods = new byte[methodsCount];
            _stream.Read(methods, 0, methodsCount);

            byte[] response = { 0x05, 0x02 };
            _stream.Write(response, 0, response.Length);
        }

        private void Authentication()
        {
            try
            {
                byte[] authBuffer = new byte[2];
                _stream.Read(authBuffer, 0, 2);
                byte version = authBuffer[0];
                byte userLen = authBuffer[1];

                byte[] userBytes = new byte[userLen];
                _stream.Read(userBytes, 0, userLen);
                string username = Encoding.ASCII.GetString(userBytes);

                byte passLen = (byte)_stream.ReadByte();
                byte[] passBytes = new byte[passLen];
                _stream.Read(passBytes, 0, passLen);
                string password = Encoding.ASCII.GetString(passBytes);

                Console.WriteLine($"Username: {username}, Password: {password}");

                bool isAuthSuccessful = ValidateUser(username, password);
                Console.WriteLine("Authentication success: {0}", isAuthSuccessful);

                byte[] pubKeyBytes = _keyManager.GetPublicKeyBytes();
                int pubKeyLen = pubKeyBytes.Length;
                byte[] authResponse = new byte[4 + pubKeyLen];

                authResponse[0] = 0x01;
                authResponse[1] = isAuthSuccessful ? (byte)0x00 : (byte)0x01;
                authResponse[2] = (byte)(pubKeyLen >> 8);
                authResponse[3] = (byte)(pubKeyLen & 0xFF);

                Buffer.BlockCopy(pubKeyBytes, 0, authResponse, 4, pubKeyBytes.Length);

                _stream.Write(authResponse, 0, authResponse.Length);

                if (!isAuthSuccessful)
                {
                    Console.WriteLine("Authentication failed. Closing connection.");
                    _client.Close();
                }
                else
                {
                    ReceiveEncryptedAESKey();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error during authentication: " + ex.Message);
                _client.Close();
            }
        }


        private void HandleRequest()
        {
            byte[] buffer = new byte[4];
            _stream.Read(buffer, 0, 4);

            if (buffer[1] == 0x01)
            {
                TcpServer.HandleConnect(_stream, _client, buffer, _aesKey, _aesIV);
            }
            else if (buffer[1] == 0x03)
            {
                UdpServer.HandleUdpAssociate(_stream, _client, _aesKey, _aesIV);
            }
        }

        private void ReceiveEncryptedAESKey()
        {
            byte[] lenBuffer = new byte[2];
            int bytesRead = _stream.Read(lenBuffer, 0, 2);
            if (bytesRead != 2)
            {
                throw new IOException("Failed to read the length of the encrypted AES key.");
            }

            int aesKeyLength = (lenBuffer[0] << 8) | lenBuffer[1];

            byte[] encryptedAESKey = new byte[aesKeyLength];
            bytesRead = _stream.Read(encryptedAESKey, 0, aesKeyLength);
            if (bytesRead != aesKeyLength)
            {
                throw new IOException("Failed to read the encrypted AES key.");
            }
            _aesKey = _keyManager.DecryptData(encryptedAESKey);

            byte[] encryptedIV = new byte[16];
            bytesRead = _stream.Read(encryptedIV, 0, encryptedIV.Length);
            if (bytesRead != encryptedIV.Length)
            {
                throw new IOException("Failed to read the IV.");
            }

            // 解密 IV（如果需要）
            _aesIV = encryptedIV;

            Console.WriteLine("Received and decrypted AES key: " + BitConverter.ToString(_aesKey));
            Console.WriteLine("Received IV: " + BitConverter.ToString(_aesIV));
        }

        // 初始化数据库
        private void InitializeDatabase()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                string createTableQuery = @"
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL
                    );
                    ";

                using (var command = new SqliteCommand(createTableQuery, connection))
                {
                    command.ExecuteNonQuery();
                }

                string insertUsersQuery = @"
                    INSERT OR IGNORE INTO users (username, password) VALUES ('user', 'pass');
                    INSERT OR IGNORE INTO users (username, password) VALUES ('root', 'root');
                ";

                using (var command = new SqliteCommand(insertUsersQuery, connection))
                {
                    command.ExecuteNonQuery();
                }
            }
        }

        // 验证用户凭据
        private bool ValidateUser(string username, string password)
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                string query = "SELECT COUNT(*) FROM users WHERE username = @username AND password = @password";
                using (var command = new SqliteCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@username", username);
                    command.Parameters.AddWithValue("@password", password); // 注意：实际应用中应对密码进行哈希处理

                    int userCount = Convert.ToInt32(command.ExecuteScalar());
                    return userCount > 0;
                }
            }
        }
    }
}
