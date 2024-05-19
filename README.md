# Socks5 Proxy Tool

System.Net.Sockets

System.Security.Cryptography

### 1. 客户端与服务端的交互流程

#### 1.1. 握手阶段（Handshake）

1. **客户端发送握手请求**：
   - 客户端发送一个版本识别和方法选择消息给服务端。
   - 数据格式：
     ```
     +----+----------+----------+
     |VER | NMETHODS | METHODS  |
     +----+----------+----------+
     | 1  |    1     | 1 to 255 |
     +----+----------+----------+
     ```
     - VER: SOCKS版本号，0x05表示版本5。
     - NMETHODS: 客户端支持的认证方法数量。
     - METHODS: 客户端支持的认证方法列表。
     - `0x00` - 无需认证（No authentication required）
     - `0x01` - GSSAPI
     - `0x02` - 用户名/密码认证（Username/Password authentication）
     - `0x03` 至 `0x7F` - 为IANA分配的保留值（Reserved for IANA assignment）
     - `0x80` 至 `0xFE` - 为私人方法保留（Reserved for private methods）
     - `0xFF` - 无可接受的方法（No acceptable methods）
     
     **客户端支持两种认证方法：无需认证和用户名/密码认证。**那么握手请求如下所示：
     
     ```
     +----+----------+----------+----------+
     |VER | NMETHODS |  METHOD  |  METHOD  |
     +----+----------+----------+----------+
     | 05 |    02    |    00    |    02    |
     +----+----------+----------+----------+
     ```
     
     - `0x05`：协议版本号（Socks5）。
     - `0x02`：支持的认证方法数量（2种）。
     - `0x00`：无需认证。
     - `0x02`：用户名/密码认证。
     

2. **服务端发送选择的认证方法**：
   
   - 服务端从客户端提供的方法中选择一个，并发送选择的认证方法消息。
   - 数据格式：
     ```
     +----+--------+
     |VER | METHOD |
     +----+--------+
     | 1  |   1    |
     +----+--------+
     ```
     - VER: SOCKS版本号，0x05表示版本5。
     - METHOD: 服务端选择的认证方法。

     **服务器收到客户端的握手请求后，会选择一种认证方法并发送响应。响应的格式如下：**
     
     ```
     +----+--------+
     |VER | METHOD |
     +----+--------+
     | 05 |    2   |
     +----+--------+
     ```

#### 1.2. 用户认证阶段（Authentication）（如果需要）

1. **客户端发送用户名和密码**：
   
   - 如果服务端选择的认证方法为用户名和密码，客户端发送用户名和密码。
   - 数据格式：
     ```
     +----+------+----------+------+----------+
     |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     +----+------+----------+------+----------+
     | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     +----+------+----------+------+----------+
     ```
     - VER: 0x01表示用户名/密码子协商版本。
     - ULEN: 用户名长度。
     - UNAME: 用户名。
     - PLEN: 密码长度。
     - PASSWD: 密码。
   
2. **服务端响应认证结果**：
   
   - 服务端响应认证是否成功。
   - 数据格式：
     ```
     +----+--------+
     |VER | STATUS |
     +----+--------+
     | 1  |   1    |
     +----+--------+
     ```
     - VER: 0x01表示用户名/密码子协商版本。
     - STATUS: 0x00表示成功，其他值表示失败。

#### 1.3. 请求阶段（Request）

1. **客户端发送请求**：
   
   - 客户端发送连接请求（CONNECT），绑定请求（BIND）或UDP关联请求（UDP ASSOCIATE）。
   - 数据格式：
     ```
     +----+-----+-------+------+----------+----------+
     |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
     +----+-----+-------+------+----------+----------+
     | 1  |  1  |  0x00 |  1   | Variable |    2     |
     +----+-----+-------+------+----------+----------+
     ```
     - VER: SOCKS版本号，0x05表示版本5。
     - CMD: 命令类型（0x01 = CONNECT，0x02 = BIND，0x03 = UDP ASSOCIATE）。
     - RSV: 保留，必须设置为0x00。
     - ATYP: 地址类型（0x01 = IPv4，0x03 = 域名，0x04 = IPv6）。
     - DST.ADDR: 目标地址（根据ATYP的值决定长度）。
     - DST.PORT: 目标端口（2字节）。
   
2. **服务端响应请求**：
   - 服务端处理请求并返回应答。
   - 数据格式：
     ```
     +----+-----+-------+------+----------+----------+
     |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
     +----+-----+-------+------+----------+----------+
     | 1  |  1  |  0x00 |  1   | Variable |    2     |
     +----+-----+-------+------+----------+----------+
     ```
     - VER: SOCKS版本号，0x05表示版本5。
     - REP: 应答字段（0x00 = 成功，0x01至0x08为各种失败原因）。
     - RSV: 保留，必须设置为0x00。
     - ATYP: 地址类型（0x01 = IPv4，0x03 = 域名，0x04 = IPv6）。
     - BND.ADDR: 绑定地址（服务端的绑定地址，根据ATYP的值决定长度）。
     - BND.PORT: 绑定端口（2字节）。

#### 1.4. 数据转发阶段（Data Transfer）

- 客户端和服务端之间的数据通过代理服务器进行转发。在此阶段，需要进行数据的加密和解密。

### 2. 数据加密和解密
使用对称加密算法（如AES）对数据进行加密和解密。

#### 加密数据
```csharp
public byte[] EncryptData(byte[] data, byte[] key, byte[] iv)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using (MemoryStream ms = new MemoryStream())
        {
            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cs.Write(data, 0, data.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }
    }
}
```

#### 解密数据
```csharp
public byte[] DecryptData(byte[] data, byte[] key, byte[] iv)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = key;
        aes.IV = iv;
        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        using (MemoryStream ms = new MemoryStream(data))
        {
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    cs.CopyTo(output);
                    return output.ToArray();
                }
            }
        }
    }
}
```

