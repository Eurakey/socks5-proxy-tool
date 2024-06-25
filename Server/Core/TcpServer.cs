using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using NLog;
using Server.Utils;
using static Utils.AesEncryption;

namespace Server.Core
{
    public class TcpServer
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public static void HandleConnect(NetworkStream clientStream, TcpClient client, byte[] buffer, byte[] aesKey, byte[] aesIV)
        {
            Logger.Info(BitConverter.ToString(buffer));

            string destAddress;
            int destPort;
            int addressType = buffer[3];

            if (addressType == 0x03) // Domain name
            {
                int domainLength = clientStream.ReadByte();
                byte[] domainBytes = new byte[domainLength];
                clientStream.Read(domainBytes, 0, domainLength);
                string domainName = Encoding.ASCII.GetString(domainBytes);
                destPort = NetworkUtils.GetDestinationPort(clientStream);

                destAddress = Dns.GetHostAddresses(domainName).FirstOrDefault()?.ToString();
                if (destAddress == null)
                {
                    throw new Exception($"Failed to resolve domain: {domainName}");
                }
                Logger.Info($"Domain: {domainName}, IP: {destAddress}, Port: {destPort}");
            }
            else // IPv4 or other
            {
                destAddress = NetworkUtils.GetDestinationAddress(clientStream, (byte)addressType);
                destPort = NetworkUtils.GetDestinationPort(clientStream);
                Logger.Info($"{destAddress}:{destPort}");
            }

            TcpClient destClient = new TcpClient(destAddress, destPort);
            NetworkStream serverStream = destClient.GetStream();
            
            byte[] connectResponse = CreateConnectResponse(destAddress, destPort, addressType);
            clientStream.Write(connectResponse, 0, connectResponse.Length);
            Logger.Info("Connection response sent.");

            RelayData(clientStream, serverStream, aesKey, aesIV);
        }

        private static void RelayData(NetworkStream clientStream, NetworkStream serverStream, byte[] aesKey, byte[] aesIV)
        {
            byte[] buffer = new byte[8192];
            int bytesRead = 0;

            try
            {
                Logger.Info("RelayData started");

                while ((bytesRead = clientStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] decryptedData = DecryptWithAES(buffer.Take(bytesRead).ToArray(), aesKey, aesIV);
                    string decryptedString = Encoding.ASCII.GetString(decryptedData);
                    Logger.Info("Request: " + decryptedString);

                    serverStream.Write(decryptedData, 0, decryptedData.Length);

                    MemoryStream responseStream = new MemoryStream();
                    while ((bytesRead = serverStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        responseStream.Write(buffer, 0, bytesRead);
                    }

                    byte[] responseData = responseStream.ToArray();
                    byte[] encryptedData = EncryptWithAES(responseData, aesKey, aesIV);

                    int encryptedDataLength = encryptedData.Length;
                    byte[] lengthBytes = new byte[3];
                    lengthBytes[0] = (byte)((encryptedDataLength >> 16) & 0xFF);
                    lengthBytes[1] = (byte)((encryptedDataLength >> 8) & 0xFF);
                    lengthBytes[2] = (byte)(encryptedDataLength & 0xFF);

                    clientStream.Write(lengthBytes, 0, lengthBytes.Length);
                    clientStream.Write(encryptedData, 0, encryptedData.Length);

                    string decryptedResponseString = Encoding.ASCII.GetString(responseData);
                    // Logger.Info("Response: " + decryptedResponseString);
                }
            }
            catch (Exception ex)
            {
                Logger.Error("Exception in RelayData: " + ex.Message);
            }
            finally
            {
                Logger.Info("Connection closed");
            }
        }

        private static byte[] CreateConnectResponse(string destAddress, int destPort, int addressType)
        {
            byte[] response;
            if (addressType == 0x03)
            {
                response = new byte[10 + destAddress.Length];
                response[0] = 0x05;
                response[1] = 0x00;
                response[2] = 0x00;
                response[3] = 0x03;
                response[4] = (byte)destAddress.Length;

                byte[] addrBytes = Encoding.ASCII.GetBytes(destAddress);
                Buffer.BlockCopy(addrBytes, 0, response, 5, addrBytes.Length);

                byte[] portBytes = BitConverter.GetBytes((ushort)destPort);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(portBytes);
                }
                Buffer.BlockCopy(portBytes, 0, response, 5 + addrBytes.Length, portBytes.Length);
            }
            else
            {
                response = new byte[10];
                response[0] = 0x05;
                response[1] = 0x00;
                response[2] = 0x00;
                response[3] = (byte)addressType;

                byte[] addrBytes = IPAddress.Parse(destAddress).GetAddressBytes();
                Buffer.BlockCopy(addrBytes, 0, response, 4, addrBytes.Length);

                byte[] portBytes = BitConverter.GetBytes((ushort)destPort);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(portBytes);
                }
                Buffer.BlockCopy(portBytes, 0, response, 8, portBytes.Length);
            }

            Logger.Info($"Created connect response: {BitConverter.ToString(response)}");
            return response;
        }
    }
}
