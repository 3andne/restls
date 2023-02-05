# Restls

For more details regarding the protocol:  
[Restls: A Perfect Impersonation of TLS Handshake](./Restls%3A%20A%20Perfect%20Impersonation%20of%20TLS%20Handshake.md)

[Restls: 对TLS握手的完美伪装](./Restls%3A%20%E5%AF%B9TLS%E6%8F%A1%E6%89%8B%E7%9A%84%E5%AE%8C%E7%BE%8E%E4%BC%AA%E8%A3%85.md)

To build it from source:

```
cargo build --release
```

Basic usage:
```
USAGE:
    restls --forward-to <forward-to> --listen <listen> --log-level <log-level> --password <password> --server-hostname <server-hostname>
```

Currently only TLS 1.3 is implemented. TLS 1.2 remains a work in progress.

To deploy a Restls Service:
1. Start the shadowsocks server:
    ```
    ss-server -p 8888 -k [YOUR_SS_PASSWORD]
    ```
2. Start the Restls server:
   ```
   restls -s "www.microsoft.com" -l "0.0.0.0:443" -p [YOUR_RESTLS_PASSWORD] -f "127.0.0.1:8888"
   ```
3. Define a restls proxy in [Clash.Meta Restls fork](https://github.com/3andne/Clash.Meta#restls)
   ```
   - name: restls
     type: ss
     server: [YOUR_SERVER_IP]
     port: 443
     cipher: chacha20-ietf-poly1305
     password: [YOUR_SS_PASSWORD]
     plugin: restls
     plugin-opts:
         host: "www.microsoft.com" # Must be a TLS 1.3 server
         password: [YOUR_RESTLS_PASSWORD]
         version-hint: "tls13"
   ```