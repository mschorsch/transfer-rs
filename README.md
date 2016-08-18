# transfer-rs
Easy file sharing server

![](http://i.imgur.com/yNkUhbv.png)

# Usage (file sharing from the command line)

* PUT /upload/[filename]
```shell
curl --upload-file [FILENAME] https://localhost:8080/upload/[FILENAME]
```

```shell
cat [FILENAME] | gpg -ac -o- | curl -X PUT --upload-file https://localhost:8080/upload/[FILENAME]
```

* POST /upload
```shell
curl -i -X POST -H "Content-Type: multipart/form-data" -F "data=@[FILENAME]" https://localhost:8080/upload/[FILENAME]
```

* GET /download/[token]/[filename]
```shell
 curl --remote-name https://localhost:8080/download/[TOKEN]/[FILENAME]
```

# Installation

Install [Rust](https://www.rust-lang.org/en-US/downloads.html)
```
curl -sSf https://static.rust-lang.org/rustup.sh | sh
```

Clone this repository
```
git clone [REPO]
```

Install `OpenSSL`
```
apt-get install openssl libssl-dev
```

Build the server
```rust
cargo build --release
```

Run (http)
```
./target/release/transer-rs -p 8080
```
or (https)
```
./target/release/transer-rs -p 8080 -ssl --ssl [CERT_PATH] --ssl-key [KEY_PATH]
```

# Command line options
```
USAGE:
    transfer-rs [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
        --ssl        Enables ssl
    -V, --version    Prints version information

OPTIONS:
    -b, --basedir <BASEDIR>                         Sets the base directory [default: /tmp/]
        --loglevel <LOGLEVEL>                       Sets the log level [default: info]  [values: error, warn, info,
                                                    debug, trace]
    -p, --port <PORT>                               Sets the server port
        --ssl-cert <SSL-CERTIFICATE>                Sets the ssl certificate
        --ssl-cert-chain <SSL-CERTIFICATE-CHAIN>    Sets the ssl certificate chain
        --ssl-key <SSL-PRIVATE-KEY>                 Sets the ssl private key
        --storage <STORAGE>                         Sets the storage provider [default: local]  [values: local]
```

# Similar projects
* [transfer.sh](https://transfer.sh/ "https://transfer.sh/")

# License
MIT