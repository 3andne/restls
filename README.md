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