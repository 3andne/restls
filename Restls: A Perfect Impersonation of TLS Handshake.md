# Restls: A Perfect Impersonation of TLS Handshake

`Authored by: 3andne`

## Introduction

GFW and circumvention technologies have gone through several iterations over the years. In the early days, using any VPN protocol could achieve circumvention. As GFW advanced, typical VPNs such as OpenVPN were precisely identified and even blocked at startup. In this context, protocols such as Shadowsocks/VMess emerged, which encrypt all packages and have no obvious characteristics and a very concise handshake process. These are unknown encrypted data streams for GFW. The original version of Shadowsocks/VMess was not blocked for several years until the end of 2018 when GFW started to block them on a large scale based on the design flaws of these protocols and the characteristics of proxy activity. Since then, TLS-based proxies gradually became mainstream, with Trojan as a representative. Its idea is very simple - disguise the proxy server as an HTTPS server. The server has a domain name and a certificate issued by a CA. The client accesses the server like visiting a HTTPS website by first completing the TLS handshake, and then provides verification information (i.e., password) in the first Application Data Record. The design of sending the password in plain text directly to the server does not undermine the protocol because TLS provides confidentiality, integrity protection and can defend against various attacks. If the GFW actively probes the proxy server, it will be recognized by the server and return the content of the disguised website because it cannot provide a password. Therefore, the protocol can defend against active detection. Trojan and similar protocols have also been safe from blocking for several years.

At the end of 2022, after the latest round of upgrades, the firewall began blocking TLS based protocols. According to speculation, there may be two bases for the blockage:

1. Based on the traffic behavior of a proxy client - high traffic, long connection, pattern of TLS handshake after the Trojan connection is established, etc.
2. Based on the characteristics of the disguised website - often using cheap or free domains and using free certificates issued by let's encrypt.

Regarding the second issue (referred to as the whitelist), @ihciah provided ShadowTLS as a solution.

## ShadowTLS

ShadowTLS server itself does not have a domain or certificate, its purpose is to disguise itself as a mainstream (in-whitelist) website.

In order to achieve this goal (taking the example of disguising as `example.com`), the client needs to send a TLS handshake request to the server. The server then forwards the request directly to `example.com` and returns the response to the client. In the eyes of the GFW, the proxy server can complete the handshake to `example.com`, so the proxy server is `example.com`.

After the handshake is complete, the client will start sending the real packets that need to be proxied by the server. These packets will be added with the TLS `Application Data Record (0x17)` header. In order to authenticate itself, the client needs to calculate an HMAC using the pre-shared password for all packets sent by the server during the handshake. This HMAC will be inserted into the first application data record sent. The server can distinguish its client from the browser or GFW through the HMAC, and sends these packets (excluding the HMAC) and all subsequent packets to the underlying proxy tool (such as shadowsocks). If the server cannot see the HMAC in the incoming packets, it will continue to forward these packets to `example.com` and return the response, thus appearing to be completely identical to the `example.com` server.

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

## The Issues of ShadowTLS

ShadowTLS provides a valuable solution for whitelist circumvention, but the protocol itself has significant issues, as it only provides client authentication and not server authentication. As pointed out by @CoiaPrant233:

```
Browser --> Real TLS server ✅
Browser --> ShadowTLS server ✅ (client authentication, defense against active probing)
ShadowTLS client --> ShadowTLS server ✅
ShadowTLS client --> Real TLS server ❌
```

Once the TLS handshake is completed, the ShadowTLS client will abandon the encrypted TLS channel and send proxy data disguised as TLS Application Data Record. However, if the recipient is a real TLS server, this record will inevitably fail the MAC check, resulting in the server sending a TLS Alert or connection reset.

According to @CoiaPrant233's ideas, firewalls can detect ShadowTLS as follows:

1. Target on some suspicious target IPs (based on proxy behavior)
2. Capture the TLS ClientHello and find out its target domain name
3. Redirect packets to a real server for the target domain name
4. Observe whether the server sends an Alert or resets the connection after the TLS handshake
5. Repeat multiple times to confirm the assumption.

## Restls

To address the issue of ShadowTLS not providing two-way authentication, we have designed the Restls protocol, which stands for restless, with the hope that it will keep GFW designers restless. This protocol is compatible with TLS1.2 and TLS1.3 and can disguise the server as any website in the whitelist. During the TLS handshake, it secretly performs two-way authentication between the client and server. The authentication process introduces no new characteristics and achieves a perfect impersonation of the TLS handshake.*

restls server: https://github.com/3andne/restls  
restls client (a fork of clash.meta): https://github.com/3andne/Clash.Meta  
restls tls library (client-side): https://github.com/3andne/restls-client-go  

*Restls (as well as ShadowTLS) only targets the handshake process, and has not yet addressed issues such as the ClientHello fingerprinting. We'll work on that later.

### Overview

We will go over each stage in the following sections, but for now here's an overview of the process.

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
     [HMAC_5 | Data] ----->     {Finished}      ----->
                                (observe HMAC_5)
                     <---->     [Data]          <---->   Shadowsocks Server
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
     {Data}          <---->        (Relay)      <---->  Shadowsocks Server
```

### Client Authentication

In the clienthello (the first packet sent by the client), we complete the client authentication. The key of the HMAC is `restls_secret`. We'll use the terminology from rfc8446.

For Restls over TLS 1.3:
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

For Restls over TLS 1.2:
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

#### Discussion

Replay attacks have always been an important threat in protocol design. ShadowTLS uses the challenge-response model to complete client authentication to prevent replay attacks. In addition to challenge-response, common methods for preventing replay attacks include using timestamps to generate authentication information (such as HMAC(timestamp)). It has been found that using timestamps to prevent replay attacks is difficult. Due to the delay from the client sending the request to the request being received, the authentication information often has a short validity period (such as 2 seconds). Attackers can successfully replay during this validity period. Even if the same authentication information is not allowed, the "replay" package constructed by the GFW can even reach the server before the client-sent package. The GFW controls the only traffic outlet anyways.

Restls needs to complete client authentication early in the handshake to make server authentication possible, and cannot use challenge response. Nor can we use timestamps based authentication.
We adopt a third method to defend replay attacks, **by designing the authentication information into a signature of the TLS client public key (i.e. key_share, pre_shared_key, ClientDiffieHellmanPublic, SessionTicket)**. 
In this way, although an attacker can use this authentication token and other information in the ClientHello for replay, it cannot complete the subsequent TLS handshake without the client secret key. That's how the replay attack is defended. By deeply integrated with the TLS protocol, Restls transfers the responsibility of defending against replay attacks to the certificate provider and avoids the replay problem.
Essentially, **Restls' authentication information is a private key unknown to the attacker – Restls proves that the client has the public key, and TLS proves that the client has the private key for that public key**.
* In elliptic curve cryptography, public and private keys have one-to-one correspondence. It is not possible to forge another usable private key given the public key, thus it's not viable for a replay attacker to complete the subsequent handshake by all means.
* In TLS1.2, the client provides its own public key after the clientHello (in ClientKeyExchange), but Restls requires the client to provide the HMAC of its public key in the clientHello, therefore the client MUST generate the client public key at the same time as the clientHello.
  * For TLS 1.2 ClientKeyExchange using ECDHE, generating the client public key is essentially generating a random number. It does not depend on information provided by the server. However, ECDHE has four different curves, and the client needs to predict which curve will be used by the server and client later. Usually, all communications between a device and a specific server use a fixed curve, so this information is not difficult to obtain.
  * For TLS 1.2 ClientKeyExchange using RSA, the server's certificate is required to be obtained first. It is theoretically impossible to obtain this information during the clientHello, thus Restls does not support RSA-based ClientKeyExchange. Given that RSA ClientKeyExchange cannot provide forward secrecy, mainstream TLS servers have phased it out. It will not impact the compatibility of Restls.

In Restls, the authentication information is stored in the `ClientHello.legacy_session_id`, due to:

1. According to rfc 8446 D.4, all clients supporting TLS1.3 are required to provide a non-empty legacy_session_id, which is usually 32 bytes in length and exists in all ClientHello messages generated by browsers.
2. The value itself is not used by the TLS protocol.
3. Its value is protected by the TLS protocol and cannot be tampered with by a middleman.

### Server Authentication

The server authentication in Restls takes place after client authentication. The idea is that for an already authenticated client, the encrypted content of the first package after the server `change_cipher_spec` is modified in a way that the client can recover. When the client receives the package, it first tries to undo the changes made by the server,
* If the "recovered" content can be decrypted, the client can confirm the server.
* If the package cannot be successfully decrypted after the undoing, the client can confirm that the peer is not a Restls server. The client then tries to decrypt the original response from the server again to continue the handshake process. 

In TLS1.3, this package is the `EncryptedExtensions`, and in TLS 1.2, this package is the `ServerFinished`.

More specifically:
For Restls over TLS 1.3,
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
UndoRestlsServerAuth = HMAC_4 (16 Bytes) ^ RestlsServerAuth


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

#### Discussion

Restls only sends `RestlsServerAuth` to authenticated clients, and does nothing to browsers or active probes. 

Note that Restls might send `RestlsServerAuth` to replay attackers:
1. For replay attackers in TLS 1.2 Full-handshake, because they cannot send the correct `ClientFinished`, their replay attack will be terminated before `RestlsServerAuth` is sent and does not pose a threat.
2. For replay attackers in TLS 1.2 resumption and TLS 1.3, since they do not possess the client private key, they cannot detect any changes no matter how we modify the contents of the package, so they do not pose a threat.
It is worth noting that the packages (`Finished` or `EncryptedExtensions`) upon which RestlsServerAuth relies often have specific lengths. Inserting the authentication field into the package may create new characteristics. Therefore, Restls uses XOR to hide the authentication field.

Using XOR makes implementation more difficult, since some ciphers have state-based implementations and cannot be recovered once decryption fails. A relatively simple workaround is to prepare another cipher objects with the identical state as a fallback in case of a decryption failure.

### Client Re-authentication

In TLS 1.2 resumption and TLS 1.3, `ClientFinished` is the last compulsory step in the handshake process, where the client uses the record to prove that it possesses the corresponding private key. However, the TLS server does not send a confirmation record to the client after receiving the "ClientFinished". Thus, Restls cannot confirm through the handshake process whether `ClientFinished` is problematic. The Restls server may wait for a period of time to see if the TLS server sends a `TLS Alert Record`, but how long this period should be is not an easy decision to make, and this clearly is not an elegant solution. Therefore, similar to the approach in `ShadowTLS`, the Restls client needs to insert an authentication field in the header of the first `Application Data Record` after the handshake to indicate its identity.

Restls over TLS 1.3 or TLS 1.2 resumption
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
     [HMAC_5 | Data] ----->     {Finished}      ----->
                                (observe HMAC_5)
                     <---->     [Data]          <---->   Shadowsocks Server
where
HMAC_5 = HMAC(ServerRandom | ServerRandom)
```