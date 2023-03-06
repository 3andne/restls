# Restls - 对TLS的完美伪装

`作者: 3andne`

## 引言

防火墙和翻墙技术在多年里经历了数次技术迭代。在早期，使用任何一个VPN协议都可以实现翻墙，随着防火墙的升级，典型的VPN（例如OpenVPN）被精准识别，甚至做到了开机即封禁。在这样的背景下，Shadowsocks/VMess等协议应运而生，这些协议所有的包都经过加密，没有明显的特征，握手过程非常精简，对于防火墙而言，这些都是协议未知的加密数据流。原始版本的Shadowsocks/VMess在数年内没有被被封杀的烦恼，直到18年底，防火墙基于这些协议本身设计上的漏洞，以及代理活动难以隐蔽的流量特征，开始对他们进行大规模封杀。在这次封杀之后，基于TLS的代理渐渐成为主流，其中具有代表性的是Trojan，它的思路非常简单 - 把代理服务器伪装成一个HTTPS服务器，服务器本身拥有域名以及CA签发的证书，客户端像访问一个网站一样，先与服务器完成TLS握手，然后在第一个application data包提供验证信息（即password），由于TLS层提供了保密性、完整性保护并能够防御各类攻击，直接向服务器发送密码的明文这样简明的设计并不会降低安全性；如果非客户端访问代理服务器，由于它无法提供password，代理服务器能将其识别，并返回伪装网站的内容，因此协议能够防御主动探测。Trojan及类似思路的协议在数年内也免于被封杀。

在2022年底，防火墙在最新一轮升级后，开始封杀Trojan类协议。根据猜测，封杀的依据可能有两种：
1. 根据代理产生的流量行为 - 大流量、长连接、trojan连接建立后模式确定的TLS握手等
2. 根据伪装站的特征 - 往往使用便宜或免费的域名，使用由let's encrypt签发的免费证书

针对第二个问题（简称白名单），[@ihciah](https://github.com/ihciah)提供了[ShadowTLS](https://github.com/ihciah/shadow-tls)作为解决方案。

## ShadowTLS简介

ShadowTLS服务器本身没有域名，没有证书，它的目的是把自己伪装成一个主流（白名单内）网站，因此免于封杀。

为了达到这个目的（以伪装成example.com为例），客户端需要向服务器发送TLS握手请求，服务器则把这个请求原封不动转发给example.com，并把回包返回给客户端，在墙看来，代理服务器可以完成针对example.com的握手，那么代理服务器就是example.com。

在握手结束后，客户端会开始向服务器发送真正需要被代理的包，这些包会被加上TLS application data的包头；为了认证自己，客户端需要把握手过程中服务器发过来的所有包，用预共享的password计算一个HMAC，在发送的第一个application data包头插入这个HMAC，当服务器看到这个HMAC时，就能确定这确实是它的客户端，而非浏览器或防火墙的探测，服务器会把这个包（除了HMAC）以及之后所有的包，发给背后的代理工具（比如shadowsocks），从而实现代理的目的；如果服务器在到来的包里看不到这个HMAC，它就会继续把这些包转发给example.com，并返回example.com的回包，从而表现得与example.com的服务器完全一致。

```
                          ShadowTLS-1.3-Shadowsocks
    ShadowTLS Client          ShadowTLS Server          example.com Server

    ClientHello      ----->       (Relay)        ----->
                                                         ServerHello
                                                         {EncryptedExtensions}
                                                         {CertificateRequest*}
                                                         {Certificate*}
                                                         {CertificateVerify*}
                     <-----       (Relay)        <-----  {Finished}              
    {Finished}       ----->       (Relay)        ----->
                     <-----       (Relay)        <-----  [NewSessionTicket]
    [HMAC+Data]      ----->  (Verify HMAC)[DATA] -----> Shadowsocks Server
    [Data]           <---->       [DATA]         <----> Shadowsocks Server
```

## ShadowTLS-V2的问题

ShadowTLS为解决白名单提供了一个宝贵的思路，但协议本身存在无法忽视的问题，即协议仅设计了针对客户端的认证，没有针对服务端的认证，根据所@CoiaPrant233指出：
```
浏览器 --> 真实TLS服务器 ✅
浏览器 --> ShadowTLS服务器 ✅ （客户端认证、防御主动探测）
ShadowTLS客户端 --> ShadowTLS服务器 ✅
ShadowTLS客户端 --> 真实TLS服务器 ❌
```
ShadowTLS协议握手过程并未提供服务端的认证，只能认定服务端是ShadowTLS。只要握手结束，客户端一定会放弃TLS建立的加密信道，发送经过伪装（伪装成TLS Application Data）的代理数据，但如果对方是真正的TLS服务器，这个包必然无法通过MAC校验，导致服务器发送TLS Alert或直接断开连接。

对此，根据@CoiaPrant233提供的思路，防火墙可以这样探测ShadowTLS：
1. 首先锁定一些可疑的目标IP（根据代理行为）
2. 截获TLS ClientHello，并获知其目标域名
3. 把该包和之后所有的包都发往目标域名的一个真正的服务器
4. 观察在TLS握手之后，服务器会不会发送Alert或直接reset connection
5. 重复多次，确认代理服务器的身份

截止本文修改时，ShadowTLS已经迭代至[v3](https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md)，实现了对TLS 1.3的双向认证，由于设计目标限制，[ShadowTLS未能对TLS1.2实现双向认证](https://github.com/ihciah/shadow-tls/issues/69#issue-1581106610)。

在目前所有致力于解决白名单封锁的协议中，只有Restls可以覆盖TLS全版本。

## Restls-V1

为了解决ShadowTLS V2上述的问题（无法提供双向认证），我们设计了Restls协议，意为Restless，**希望该协议可以让防火墙设计者们坐立不安**。  

Restls的设计目标为：

1. 兼容所有主流TLS版本(TLS1.2, TLS1.3)，可以将服务器伪装成任何一个白名单内网站。
2. 在TLS握手的同时，秘密进行客户端和服务端的双向认证，认证过程完全不引入新的特征。
3. 握手结束后，继续将代理流量伪装为普通TLS流量，防御基于包长和收发模式的流量分析，[防御篡改、重放、丢包等主动攻击](#应用数据传输认证).
4. 为客户端提供`ClientHello`伪装的能力，[将TLS指纹伪装成浏览器](https://github.com/3andne/restls-client-go)。

Restls希望在满足上述目标的同时提供高性能，但极致性能并不是我们的设计目标。

restls server: https://github.com/3andne/restls  
restls client (a fork of clash.meta): https://github.com/3andne/Clash.Meta  
restls tls library (client-side): https://github.com/3andne/restls-client-go  

### Overview

我们会在之后的部分介绍每个环节，在此展示一个流程总览。

Restls over TLS 1.3 or TLS 1.2 with resumption
```
`{}` means encrypted.

    Restls Client               Restls Server          example.com Server

     ClientHello     ----->        (Relay)      ----->
      +restls_client_auth                                ServerHello
                                                         ...
                                                         ChangeCipherSpec
                                                         {Encrypted}
                                                         ...
                                ServerHello     <-----   {Finished}  
                                (verify key_share(1.3)
                                 and psk(1.3)
                                 or session_ticket(1.2))
                                ...
                                ChangeCipherSpec
                                RestlsServerAuth
                                ...
                     <-----     {Finished}       
     try_decrypt(UndoRestlsServerAuth)
      > succeeded
     {Finished}      
     [AUTH_C_0|Data] ----->     {Finished}      ----->
                                [Data]          ----->   Shadowsocks Server
     [Data]          <-----     [AUTH_S | Data] <-----   Shadowsocks Server
     [AUTH_C | Data] ----->     [Data]          ----->   Shadowsocks Server
                                ....
```

Restls over TLS 1.2:
```
`{}` means encrypted.

    Restls Client               Restls Server          example.com Server

     ClientHello     ----->        (Relay)      ----->
      +restls_client_auth                               ServerHello
                                                        Certificate*
                                                        ServerKeyExchange*
                                                        CertificateRequest*
                     <-----        (Relay)      <-----  ServerHelloDone   
     Certificate*
     ClientKeyExchange
     CertificateVerify*
     [ChangeCipherSpec]
     Finished        ----->        
                            (verify client pub key)
                                   (Relay)      ----->  [ChangeCipherSpec]
                                                <-----  Finished
                                 [ChangeCipherSpec]
                     <-----      RestlsServerAuth
     try_decrypt(UndoRestlsServerAuth)
      > succeeded
     [AUTH_C | Data] ----->      [Data]          ----->  Shadowsocks Server
     [Data]          <-----      [AUTH_S | Data] <-----  Shadowsocks Server
                                    ....
```


### 客户端认证

我们在`ClientHello`（客户端发送的第一个包）中完成客户端认证。

我们定义`HMAC`使用`restls_secret`，并使用rfc8446的术语来描述。

对于TLS 1.3:
```
ClientHello.legacy_session_id(32 Bytes) = restls_client_auth
where restls_client_auth = HMAC_1 (16 Bytes) | random padding (16 Bytes)
      HMAC_1 = HMAC(key_share_encoded | pre_shared_key_encoded)(16 Bytes) 

|------- legacy_session_id -------|
|------ restls_client_auth -------|
+----------------+----------------+
|     HMAC_1     |     random     |
+----------------+----------------+
|       16       |       16       |
+----------------+----------------+

where
key_share_encoded is encoded from key_share (rfc 8446 4.2.8) and MUST include
all key_share entries:
+-------+--------------+-------+--------------+-------+
| group | key_exchange | group | key_exchange | ..... |
+-------+--------------+-------+--------------+-------+
|   1   |      VAR     |   1   |      VAR     | ..... |
+-------+--------------+-------+--------------+-------+
pre_shared_key_encoded is encoded from pre_shared_key (rfc 8446 4.2.11) and
MUST include all OfferedPsks:
+----------+----------+----------+-------+
| identity | identity | identity | ..... |
+----------+----------+----------+-------+
|    VAR   |    VAR   |    VAR   | ..... |
+----------+----------+----------+-------+
```

对于TLS 1.2:
```
ClientHello.legacy_session_id(32 Bytes) = restls_client_auth
where restls_client_auth = HMAC_2 (16 Bytes) | HMAC_3 (16 Bytes)
      HMAC_2 = HMAC(ClientDiffieHellmanPublic) (16 Bytes)
      HMAC_3 = HMAC(SessionTicket)(16 Bytes)

|------- legacy_session_id -------|
|------ restls_client_auth -------|
+----------------+----------------+
|     HMAC_2     |     HMAC_3     |
+----------------+----------------+
|       16       |       16       |
+----------------+----------------+

where
ClientDiffieHellmanPublic is defined in rfc5246 7.4.7,
SessionTicket is defined in rfc5077,
```

#### 讨论

重放攻击一直是协议设计需要考虑的重要因素，为了防止重放，ShadowTLS使用challenge-response来完成客户端认证。除了challenge-response外，常用的防止重放的方法也包括使用时间戳来生成认证信息（例如 HMAC(timestamp)）。在长期的实践中，人们发现使用时间戳来防止重放的思路困难重重，一方面从客户端发送请求到接收请求之间有一定延迟，因此认证字段往往会设计一段时间的有效期（比如2秒）。攻击者在有效期内进行攻击，便可以成功重放。即便是禁止同样的认证信息也无法解决问题，因为防火墙掌握了唯一的流量出口，**它构造的重放包甚至可以比客户端发送的包先一步抵达服务器**。

Restls需要在握手早期就完成客户端认证，以便为服务端认证提供可能，不能使用challenge response，我们也不能使用基于时间戳的认证方式。
因此Restls采用了第三种防止重放的思路，将**认证信息设计成了对TLS client public key（即key_share、pre_shared_key、ClientDiffieHellmanPublic、SessionTicket）的签名**。这样一来，攻击者虽然可以使用该认证信息以及ClientHello里的其他信息进行重放，但由于其没有client secret key，因此无法完成后续TLS握手，重放攻击不成立。通过与TLS协议的深度绑定，Restls把防御重放攻击的责任转移给了证书提供方，规避了重放问题。**本质上，Restls的认证信息是不被攻击者所知的私钥 - Restls证明客户端拥有公钥，TLS证明客户端拥有该公钥的私钥。**
* 在椭圆曲线密码中，公钥和私钥一一对应，给定公钥无法构造另一个可用的私钥，因此重放攻击者通过构造私钥来完成后续握手不具有可行性。
* TLS1.2中，客户端提供自己的公钥（即ClientKeyExchange）发生在clientHello之后，但Restls要求客户端必须在clientHello中提供其公钥的HMAC，因此客户端必须在生成clientHello同时生成client public key。
  * 对于使用ECDHE的ClientKeyExchange，生成client public key约等于生成随机数，不依赖服务器提供的信息，但ECDHE有四种不同的Curve，客户端需要预测之后和服务器会使用哪一种Curve；往往一个设备和特定服务器的所有通讯都会使用固定的一个curve，所以该信息不难获取。
  * 对于使用RSA的ClientKeyExchange，需要先获得服务器的证书，但服务器向客户端发送证书发生在serverHello之后，在clientHello时该信息从理论上无法获得，因此Restls不支持基于RSA的ClientKeyExchange；鉴于RSA Key Exchange无法提供forward secrecy，主流TLS服务器已将其淘汰，因此这并不会影响Restls的兼容性。

Restls的认证信息被存在`legacy_session_id`中，因为：
1. 根据rfc 8446 D.4，所有支持TLS1.3的客户端都需要提供一个非空的`legacy_session_id`，而这个字段往往是32 Bytes，该字段在所有浏览器产生的ClientHello中皆存在。
2. 该值本身不被TLS协议所使用。
3. 其值受到TLS协议的保护，不可被中间人篡改。

### 服务端认证

Restls的服务端认证发生在客户端认证之后。
其思路是：对已认证的客户端，将server change_cipher_spec后第一个包的加密内容用一种客户端可以复原的方式进行修改。客户端收到包后，先尝试撤销服务端做的改动：
* 如何撤销改动后的包可以被解密，客户端便可以确认对方是Restls服务器。
* 如果撤销后的包并不能被成功解密，那么客户端便可确认对方并不是一个Restls服务器，客户端会用服务器原始的回包再次尝试解密，以继续握手过程。

在TLS1.3中，这个包是`{EncryptedExtensions}`，在TLS 1.2中，这个包是`ServerFinished`
具体来说：

TLS 1.3:
```
`{}` means encrypted.

    Restls Client               Restls Server          example.com Server

     ClientHello     ----->        (Relay)      ----->
                                                         ServerHello
                                                         ChangeCipherSpec
                                                         {EncryptedExtensions}
                                                         {CertificateRequest*}
                                                         {Certificate*}
                                                         {CertificateVerify*}
                                ServerHello     <-----   {Finished}  
                                ChangeCipherSpec
                                RestlsServerAuth
                                {CertificateRequest*}
                                {Certificate*}
                                {CertificateVerify*}
                     <-----     {Finished}       

where
HMAC_4 = HMAC(ServerRandom) (16 Bytes)
RestlsServerAuth = {EncryptedExtensions} ^ HMAC_4 (16 Bytes)
```

TLS 1.2 (Full Handshake):
```
`{}` means encrypted.

    Restls Client               Restls Server          example.com Server

     ClientHello     ----->        (Relay)      ----->
                                                        ServerHello
                                                        Certificate*
                                                        ServerKeyExchange*
                                                        CertificateRequest*
                     <-----        (Relay)      <-----  ServerHelloDone   
     Certificate*
     ClientKeyExchange
     CertificateVerify*
     [ChangeCipherSpec]
     Finished        ----->        (Relay)      ----->
                                                        [ChangeCipherSpec]
                                                <-----  Finished
                                 [ChangeCipherSpec]
                     <-----      RestlsServerAuth

where
HMAC_4 = HMAC(ServerRandom) (16 Bytes)
RestlsServerAuth = Finished ^ HMAC_4 (16 Bytes)
```

Restls Client:
```
A successful authentication: 
    Restls Client                          Restls Server 
                                              .....
                                          RestlsServerAuth
 try_decrypt(UndoRestlsServerAuth)    <-----   .....
  > succeeded, server verified

where
UndoRestlsServerAuth = HMAC_4 ^ RestlsServerAuth


A failed authentication: 
    Restls Client                              TLS Server 
                                                 .....
                                             RestlsServerAuth
     try_decrypt(UndoRestlsServerAuth)  <-----   .....
      > failed
     try_decrypt(RestlsServerAuth)
      > succeeded
                                        ----->
where
UndoRestlsServerAuth = HMAC_4 ^ RestlsServerAuth
```

#### 讨论

Restls只对认证过的客户端发送`RestlsServerAuth`，对于没有认证过的浏览器或主动探测不会产生影响。
对于重放攻击者，Restls也会发送`RestlsServerAuth`，其安全性需要分类讨论：
1. 对于TLS 1.2 Full-handshake的重放攻击者，由于其无法发送正确的`ClientFinished`，其重放攻击会在`RestlsServerAuth`发送前被终止，不构成威胁。
2. 对于TLS 1.2 resumption以及TLS 1.3的重放攻击者，由于其并未掌握client private key，无论怎么修改这个包的内容，它都无法察觉，因此不构成威胁。
需要注意的是，`RestlsServerAuth`所依赖的包（`Finished`、`{EncryptedExtensions}`）往往有特定的长度，因此将server认证字段插入包内可能会产生全新特征，因此Restls采用了`xor`的方式来添加认证字段。
* 使用`xor`在避免产生特征的同时，增加了实现难度。一些加密算法的实现是有状态的，一旦解密失败便无法恢复，一个比较简单的解决方案是准备两个状态相同的`cipher object`，用以替换。

### 应用数据传输认证

Restls应用数据是TLS握手之后传输的数据，这些数据也是真正的代理数据。
在早期的设计中，Restls只参与TLS握手环节并为后续应用数据提供简单的伪装，这为主动攻击留下了空间。
在Restls-V1中，我们受[ShadowTLS-V3](https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md)的启发并设计了`restls_auth_header`来实现对应用数据的保护。

```
Restls Application Data:

+----------------+------------------------+----------+-----------+
|   TLS_HEADER   |   RESTLS_AUTH_HEADER   |   DATA   |  PADDING  |
+----------------+------------------------+----------+-----------+
|        5       |           12           |    VAR   |    VAR    |
+----------------+------------------------+----------+-----------+

|---------------------- restls_auth_header -----------------------|
+---------------+---------------------+---------------------------+
|   AUTH_HMAC   |   MASKED_DATA_LEN   |   MASKED_RESTLS_COMMAND   |
+---------------+---------------------+---------------------------+
|       8       |          2          |             2             |
+---------------+---------------------+---------------------------+
```

`restls_auth_header`需要被添加在客户端和服务端发送的所有应用数据record之中，我们将依次介绍它的各个部分。

#### AUTH_HMAC

Restls通过`AUTH_HMAC`为数据传输提供有上下文的完整性保护，使得Restls可以察觉篡改、丢失以及重放等攻击。

在TLS 1.2 resumption以及TLS 1.3中，`ClientFinished`是握手过程中的最后一个强制环节，客户端使用该record来证明自己拥有对应的私钥，但TLS server在收到`ClientFinished`后，不会向client发送确认的record。

为了让Restls可以确认`ClientFinished`是否完好，我们要求在这两种情况下，客户端发送的第一个AUTH_HMAC包含`ClientFinished`的信息。

#### MASKED_DATA_LEN

`data_len`即本record中包含的data的实际长度。通过记录这个长度，Restls可以为record添加padding，为防御流量分析提供可能

明文`data_len`显然不宜直接传输，因此Restls使用xor对其进行加密。具体导出方式请见下文。

#### MASKED_RESTLS_COMMAND

`restls_command`是一系列用来要求通信对方做出相应反应的命令。  
Restls-V1 支持两种Command，分别是：
1. Noop. 即不需要任何反应
2. Response(num). 对方需要发送`num`数量的response。

与`data_len`一样，`restls_command`被使用xor进行加密之后再进行传输。

#### 流程

TLS 1.3 or TLS 1.2 resumption
```
`{}` means encrypted.

    Restls Client               Restls Server          example.com Server

     ClientHello     ----->        (Relay)      ----->
                                                         ServerHello
                                                         ...
                                                         ChangeCipherSpec
                                                         {Encrypted}
                                                         ...
                                ServerHello     <-----   {Finished}  
                                ...
                                ChangeCipherSpec
                                RestlsServerAuth
                                ...
                     <-----     {Finished}       
     try_decrypt(UndoRestlsServerAuth)
      > succeeded
     {Finished}      
     [AUTH_C_0 | Data] ----->   [Data]          ----->  Shadowsocks Server
     [Data]            <-----   [AUTH_S | Data] <-----  Shadowsocks Server
     [AUTH_C | Data]   ----->   [Data]          ----->  Shadowsocks Server
where
HMAC_C(...) = HMAC(ServerRandom | TO_SERVER_MAGIC | TO_SERVER_COUNTER | ...)
MASKED_DATA_LEN = DATA_LEN ^ HMAC_C(Data[:min(len(Data), 32)])[:2]
MASKED_RESTLS_COMMAND = RESTLS_COMMAND ^ HMAC_C(Data[:min(len(Data), 32)])[2:4]

AUTH_HMAC_C_0 = HMAC_C(ClientFinished | MASKED_DATA_LEN | MASKED_RESTLS_COMMAND | Data)
AUTH_C_0 = AUTH_HMAC_C_0 | MASKED_DATA_LEN | MASKED_RESTLS_COMMAND

AUTH_HMAC_C = HMAC_C(MASKED_DATA_LEN | MASKED_RESTLS_COMMAND | Data)
AUTH_C =  AUTH_HMAC_C | MASKED_DATA_LEN | MASKED_RESTLS_COMMAND

HMAC_S(...) = HMAC(ServerRandom | TO_CLIENT_MAGIC | TO_CLIENT_COUNTER | ...)
AUTH_HMAC_S = HMAC_S(MASKED_DATA_LEN | MASKED_RESTLS_COMMAND | Data)
AUTH_S =  AUTH_HMAC_S | MASKED_DATA_LEN | MASKED_RESTLS_COMMAND
```

TLS 1.2:
```
`{}` means encrypted.

    Restls Client               Restls Server          example.com Server

     ClientHello     ----->        (Relay)      ----->
      +restls_client_auth                               ServerHello
                                                        Certificate*
                                                        ServerKeyExchange*
                                                        CertificateRequest*
                     <-----        (Relay)      <-----  ServerHelloDone   
     Certificate*
     ClientKeyExchange
     CertificateVerify*
     [ChangeCipherSpec]
     Finished        ----->        
                            (verify client pub key)
                                   (Relay)      ----->  [ChangeCipherSpec]
                                                <-----  Finished
                                 [ChangeCipherSpec]
                     <-----      RestlsServerAuth
     try_decrypt(UndoRestlsServerAuth)
      > succeeded
     [AUTH_C | Data] ----->      [Data]          ----->  Shadowsocks Server
     [Data]          <-----      [AUTH_S | Data] <-----  Shadowsocks Server
                                    ....
where
AUTH_C and AUTH_S is defined above
```

### 补充

1. Restls不支持使用RSA Key Exchange的部分TLS 1.2 cipher。
2. Restls不支持TLS 1.3中的`HelloRetryRequest`，因为原则上ClientHelloRetry的`legacy_session_id`需要与`ClientHello`中的一致，但`key_share`可以发生变化。
