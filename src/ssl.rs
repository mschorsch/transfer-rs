use std::net::{ToSocketAddrs, SocketAddr};
use std::time::Duration;
use std::path::{PathBuf, Path};
use std::sync::Arc;

use hyper::server::Listening;
use hyper::server::Server;
use hyper::net::Fresh;
use hyper::net::Openssl;

use iron::{Protocol, Iron};

use openssl::ssl::error::SslError;
use openssl::ssl::{Ssl, SslContext, SslStream, SslMethod, SSL_VERIFY_NONE, SSL_VERIFY_PEER,
                   SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3, SSL_OP_NO_COMPRESSION};
use openssl::ssl::error::StreamError as SslIoError;
use openssl::x509::X509FileType;

pub fn start_server<C, K, R>(certificate: C, key: K, chain: Option<R>) -> Iron
    where C: AsRef<Path>,
          K: AsRef<Path>,
          R: AsRef<Path>
{
    let ssl = try!(create_openssl(certificate, key, chain));
    let mut server = try!(Server::https(sock_addr, ssl));
    let timeouts = timeouts.unwrap_or_default();
    server.keep_alive(timeouts.keep_alive);
    server.set_read_timeout(timeouts.read);
    server.set_write_timeout(timeouts.write);
    server.handle_threads(self, threads);
}

// see http://hyper.rs/hyper/v0.9.10/src/hyper/src/net.rs.html#646-649
fn create_openssl<C, K, R>(cert: C, key: K, chain: Option<R>) -> Result<Openssl, SslError>
    where C: AsRef<Path>,
          K: AsRef<Path>,
          R: AsRef<Path>
{
    let mut ctx = try!(SslContext::new(SslMethod::Sslv23));
    try!(ctx.set_cipher_list("DEFAULT"));

    try!(ctx.set_certificate_file(cert.as_ref(), X509FileType::PEM));
    try!(ctx.set_private_key_file(key.as_ref(), X509FileType::PEM));

    if chain.is_some() {
        try!(ctx.set_certificate_chain_file(chain.unwrap().as_ref(), X509FileType::PEM));
    }

    ctx.set_verify(SSL_VERIFY_NONE, None);
    Ok(Openssl { context: Arc::new(ctx) })
}
