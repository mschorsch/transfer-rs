// Mostly copied from https://github.com/iron/iron/blob/e8f646431ec65d47c2abaf66e27609bce1e64d20/src/iron.rs
// Copied http://hyper.rs/hyper/v0.9.10/src/hyper/src/net.rs.html#707-718
// Intermediate certificate added

// !! remove this module when iron supports intermidiate certificates !! 

use std::net::{ToSocketAddrs, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::path::PathBuf;

use hyper::server::Listening;
use hyper::server::Server as HyperServer;
use hyper::net::Fresh;
use hyper::server::Handler as HyperHandler;

use hyper::net::Openssl;

use iron::request::HttpRequest as IronHttpRequest;
use iron::response::HttpResponse as IronHttpResponse;
use iron::error::HttpResult as IronHttpResult;

use iron::{Request as IronRequest, Handler as IronHandler, Protocol, Timeouts};
use iron::status;

use openssl::ssl::{SslContext, SslMethod, SSL_VERIFY_NONE};
use openssl::ssl::error::SslError;
use openssl::x509::X509FileType;

pub struct TransferServer<H> {
    handler: H,
    addr: Option<SocketAddr>,
    protocol: Option<Protocol>,
}

impl<H: IronHandler> TransferServer<H> {
    pub fn new(handler: H) -> TransferServer<H> {
        TransferServer {
            handler: handler,
            addr: None,
            protocol: None,
        }
    }

    pub fn http<A: ToSocketAddrs>(mut self, addr: A) -> IronHttpResult<Listening> {
        let sock_addr = addr.to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .expect("Could not parse socket address.");

        self.addr = Some(sock_addr);
        self.protocol = Some(Protocol::Http.clone());

        let mut server = try!(HyperServer::http(sock_addr));
        let timeouts = Timeouts::default();
        server.keep_alive(timeouts.keep_alive);
        server.set_read_timeout(timeouts.read);
        server.set_write_timeout(timeouts.write);
        server.handle_threads(self, 8 * ::num_cpus::get())
    }

    pub fn https<A: ToSocketAddrs>(mut self,
                                   addr: A,
                                   certificate: PathBuf,
                                   key: PathBuf,
                                   chain_certificate: Option<PathBuf>)
                                   -> IronHttpResult<Listening> {
        let sock_addr = addr.to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .expect("Could not parse socket address.");

        self.addr = Some(sock_addr);
        self.protocol = Some(Protocol::Https {
            certificate: certificate.clone(),
            key: key.clone(),
        });

        let ssl = try!(create_openssl(certificate, key, chain_certificate));
        let mut server = try!(HyperServer::https(sock_addr, ssl));
        let timeouts = Timeouts::default();
        server.keep_alive(timeouts.keep_alive);
        server.set_read_timeout(timeouts.read);
        server.set_write_timeout(timeouts.write);
        server.handle_threads(self, 8 * ::num_cpus::get())
    }
}

// see http://hyper.rs/hyper/v0.9.10/src/hyper/src/net.rs.html#707-718
fn create_openssl<C, K, R>(certificate: C,
                           key: K,
                           chain_certificate: Option<R>)
                           -> Result<Openssl, SslError>
    where C: AsRef<Path>,
          K: AsRef<Path>,
          R: AsRef<Path>
{
    let mut ctx = try!(SslContext::new(SslMethod::Sslv23));
    try!(ctx.set_cipher_list("DEFAULT"));

    try!(ctx.set_certificate_file(certificate.as_ref(), X509FileType::PEM));
    try!(ctx.set_private_key_file(key.as_ref(), X509FileType::PEM));

    if chain_certificate.is_some() {
        try!(ctx.set_certificate_chain_file(chain_certificate.unwrap().as_ref(), X509FileType::PEM));
    }

    ctx.set_verify(SSL_VERIFY_NONE, None);
    Ok(Openssl { context: Arc::new(ctx) })
}

impl<H: IronHandler> HyperHandler for TransferServer<H> {
    fn handle(&self, http_req: IronHttpRequest, mut http_res: IronHttpResponse<Fresh>) {
        *http_res.status_mut() = status::InternalServerError;

        match IronRequest::from_http(http_req,
                                     self.addr.clone().unwrap(),
                                     self.protocol.as_ref().unwrap()) {
            Ok(mut req) => {
                self.handler
                    .handle(&mut req)
                    .unwrap_or_else(|e| {
                        error!("Error handling:\n{:?}\nError was: {:?}", req, e.error);
                        e.response
                    })
                    .write_back(http_res)
            }
            Err(e) => {
                error!("Error creating request:\n    {}", e);
                bad_request(http_res)
            }
        }
    }
}

fn bad_request(mut http_res: IronHttpResponse<Fresh>) {
    *http_res.status_mut() = status::BadRequest;

    if let Ok(res) = http_res.start() {
        let _ = res.end();
    }
}