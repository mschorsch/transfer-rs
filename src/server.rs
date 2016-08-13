// Partwise copied from https://github.com/iron/iron/blob/e8f646431ec65d47c2abaf66e27609bce1e64d20/src/iron.rs
// Copied http://hyper.rs/hyper/v0.9.10/src/hyper/src/net.rs.html#707-718
// Intermediate certificate added

// !! Remove this module when iron supports intermediate certificates !!

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

use iron::{Request as IronRequest, Handler as IronHandler, Protocol as IronProtocol, Timeouts};
use iron::status;

use openssl::ssl::{SslContext, SslMethod, SSL_VERIFY_NONE};
use openssl::ssl::error::SslError;
use openssl::x509::X509FileType;

use errors::TransferError;

#[derive(Clone)]
pub enum ExtIronProtocol {
    Http,

    Https {
        certificate: PathBuf,
        key: PathBuf,
        certificate_chain: Option<PathBuf>,
    },
}

impl ExtIronProtocol {
    pub fn with_https(certificate: PathBuf,
                      key: PathBuf,
                      certificate_chain: Option<PathBuf>)
                      -> Self {
        ExtIronProtocol::Https {
            certificate: certificate,
            key: key,
            certificate_chain: certificate_chain,
        }
    }

    fn to_iron_protocol(&self) -> IronProtocol {
        match *self {
            ExtIronProtocol::Http => IronProtocol::Http,
            ExtIronProtocol::Https { ref certificate, ref key, .. } => {
                IronProtocol::Https {
                    certificate: certificate.clone(),
                    key: key.clone(),
                }
            }
        }
    }
}

pub struct TransferServer<H> {
    handler: H,
    sock_addr: SocketAddr,
    ext_protocol: ExtIronProtocol,
    protocol: IronProtocol,
}

impl<H: IronHandler> TransferServer<H> {
    pub fn new<A: ToSocketAddrs>(handler: H,
                                 addr: A,
                                 ext_protocol: ExtIronProtocol)
                                 -> ::errors::Result<TransferServer<H>> {

        let sock_addr: SocketAddr = try!(try!(addr.to_socket_addrs()
                .map_err(|err| {
                    TransferError::from(format!("Could not initialize socket address: '{}'", err))
                })
                .map(|mut addrs| addrs.next()))
            .ok_or(TransferError::from("Could not parse socket address.")));

        let iron_protocol = ext_protocol.to_iron_protocol();

        Ok(TransferServer {
            handler: handler,
            sock_addr: sock_addr,
            ext_protocol: ext_protocol,
            protocol: iron_protocol,
        })
    }

    pub fn init(self) -> IronHttpResult<Listening> {
        let timeouts = Timeouts::default();

        let ssl_tup = match self.ext_protocol {
            ExtIronProtocol::Http => (false, None, None, None),
            ExtIronProtocol::Https { ref certificate, ref key, ref certificate_chain } => {
                (true, Some(certificate.clone()), Some(key.clone()), certificate_chain.clone())
            }
        };

        match ssl_tup {
            // HTTP
            (false, _, _, _) => {
                let mut server = try!(HyperServer::http(self.sock_addr));
                server.keep_alive(timeouts.keep_alive);
                server.set_read_timeout(timeouts.read);
                server.set_write_timeout(timeouts.write);
                server.handle_threads(self, 8 * ::num_cpus::get())
            }

            // HTTPS
            (true, cert, key, cert_chain) => {
                let ssl = try!(create_openssl(cert.unwrap(), key.unwrap(), cert_chain));

                let mut server = try!(HyperServer::https(self.sock_addr, ssl));
                server.keep_alive(timeouts.keep_alive);
                server.set_read_timeout(timeouts.read);
                server.set_write_timeout(timeouts.write);
                server.handle_threads(self, 8 * ::num_cpus::get())
            }
        }
    }
}

// see http://hyper.rs/hyper/v0.9.10/src/hyper/src/net.rs.html#707-718
fn create_openssl<C, K, R>(certificate: C,
                           key: K,
                           certificate_chain: Option<R>)
                           -> Result<Openssl, SslError>
    where C: AsRef<Path>,
          K: AsRef<Path>,
          R: AsRef<Path>
{
    let mut ctx = try!(SslContext::new(SslMethod::Sslv23));
    try!(ctx.set_cipher_list("DEFAULT"));

    try!(ctx.set_certificate_file(certificate.as_ref(), X509FileType::PEM));
    try!(ctx.set_private_key_file(key.as_ref(), X509FileType::PEM));

    // intermediate cert support
    if certificate_chain.is_some() {
        try!(ctx.set_certificate_chain_file(certificate_chain.unwrap().as_ref(), X509FileType::PEM));
    }

    ctx.set_verify(SSL_VERIFY_NONE, None);
    Ok(Openssl { context: Arc::new(ctx) })
}

impl<H: IronHandler> HyperHandler for TransferServer<H> {
    fn handle(&self, http_req: IronHttpRequest, mut http_res: IronHttpResponse<Fresh>) {
        *http_res.status_mut() = status::InternalServerError;

        match IronRequest::from_http(http_req, self.sock_addr.clone(), &self.protocol) {
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