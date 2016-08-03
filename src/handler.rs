use std::io;
use std::marker;
use std::path::Path;

use iron::prelude::*;
use iron::{AfterMiddleware, BeforeMiddleware, Handler};
use iron::status;
use iron::headers;
use iron::modifiers;
use iron::response;
use iron::mime::Mime;
use iron::error::HttpError;
use router::{NoRoute, Router};
use mime_guess;

use sanitize;
use storage::Storage;
use codec;

// health handler
//
pub fn health_handler(_: &mut Request) -> IronResult<Response> {
    Ok(Response::with((status::Ok,
                       "Approaching Neutral Zone, all systems normal and functioning.")))
}

// GET handler
//
#[derive(Debug)]
pub struct GetHandler<R, S>
    where R: io::Read + Send + Sync + 'static,
          S: Storage<R> + Clone + Send + Sync + 'static
{
    storage: S,
    _marker: marker::PhantomData<R>,
}

impl<R, S> GetHandler<R, S>
    where R: io::Read + Send + Sync + 'static,
          S: Storage<R> + Clone + Send + Sync + 'static
{
    pub fn new(storage: S) -> Self {
        GetHandler {
            storage: storage,
            _marker: marker::PhantomData,
        }
    }
}

impl<R, S> Handler for GetHandler<R, S>
    where R: io::Read + Send + Sync + 'static,
          S: Storage<R> + Clone + Send + Sync + 'static
{
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let params = req.extensions.get::<Router>().unwrap();
        let token = &params["token"];
        let ref filename = sanitize::sanitize_filename(&params["filename"]);

        let storage_result = self.storage.get(token, filename);

        match storage_result {
            Err(ref err) => {
                if self.storage.is_not_exist(err) {
                    Ok(Response::with((status::NotFound, "File not found")))
                } else {
                    error!("{}", err);
                    Ok(Response::with((status::InternalServerError, "Could not retrieve file")))
                }
            }
            Ok((reader, content_type, content_length)) => {
                let mut response = Response::with(status::Ok);
                response.headers.set(headers::ContentType(content_type));
                response.headers.set(headers::ContentLength(content_length));
                response.headers.set(headers::ContentDisposition {
                    disposition: headers::DispositionType::Attachment,
                    parameters: vec![headers::DispositionParam::Filename(
                            headers::Charset::Iso_8859_1,
                            None, // optional language tag
                            filename.clone().into_bytes()
                        )],
                });
                response.headers.set(headers::Connection::close());

                response.body = Some(Box::new(response::BodyReader(reader)));

                Ok(response)
            }
        }
    }
}


// PUT handler
//
#[derive(Debug)]
pub struct PutHandler<R, S>
    where R: io::Read + Send + Sync + 'static,
          S: Storage<R> + Clone + Send + Sync + 'static
{
    storage: S,
    _marker: marker::PhantomData<R>,
}

impl<R, S> PutHandler<R, S>
    where R: io::Read + Send + Sync + 'static,
          S: Storage<R> + Clone + Send + Sync + 'static
{
    pub fn new(storage: S) -> Self {
        PutHandler {
            storage: storage,
            _marker: marker::PhantomData,
        }
    }
}

impl<R, S> Handler for PutHandler<R, S>
    where R: io::Read + Send + Sync + 'static,
          S: Storage<R> + Clone + Send + Sync + 'static
{
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let params = req.extensions.get::<Router>().unwrap();
        let ref filename = sanitize::sanitize_filename(&params["filename"]);

        let content_length: u64 = req.headers.get::<headers::ContentLength>().map_or(0, |ct| ct.0);
        let content_type: Mime = req.headers
            .get::<headers::ContentType>()
            .map_or_else(|| get_mime_from_filename(&filename), |ct| ct.0.clone());
        let host_address = host_to_host_address(req.headers.get::<headers::Host>().unwrap()); // safe unwrap
        let token = codec::random_token();

        info!("Uploading => token: '{}', filename: '{}', content length: {}, content type: '{}'",
              token,
              filename,
              content_length,
              content_type);

        let storage_result = self.storage.put(&token,
                                              &filename,
                                              &mut req.body,
                                              &content_type,
                                              content_length);

        match storage_result {
            Err(err) => {
                error!("{}", err);
                Ok(Response::with((status::InternalServerError, "Could not save file")))
            }
            Ok(_) => {
                let msg = format!("{}://{}/{}/{}\n",
                                  req.url.scheme(),
                                  host_address,
                                  token,
                                  filename);
                Ok(Response::with((status::Ok,
                                   msg,
                                   modifiers::Header(headers::ContentType::plaintext()))))
            }
        }
    }
}

fn host_to_host_address(host: &headers::Host) -> String {
    if host.port.is_none() || host.port.unwrap() == 80u16 {
        host.hostname.to_owned()
    } else {
        format!("{}:{}", host.hostname, host.port.unwrap())
    }
}

fn get_mime_from_filename(filename: &str) -> Mime {
    mime_guess::guess_mime_type(Path::new(filename))
}

// CheckHostHeaderMiddleware
//
pub struct CheckHostHeaderMiddleware;

impl BeforeMiddleware for CheckHostHeaderMiddleware {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        match req.headers.get::<headers::Host>() {
            Some(_) => Ok(()),
            None => Err(IronError::new(HttpError::Header, (status::BadRequest, "Host header not found"))),  
        }
    }
}

// NotFoundMiddleware
//
pub struct NotFoundMiddleware;

impl AfterMiddleware for NotFoundMiddleware {
    fn catch(&self, req: &mut Request, err: IronError) -> IronResult<Response> {
        if let Some(_) = err.error.downcast::<NoRoute>() {
            let message = format!("why you calling {}?", req.url);
            Ok(Response::with((status::NotFound, message)))
        } else {
            Err(err)
        }
    }
}

// Info middleware
//
header! { (XPoweredBy, "X-Powered-By") => [String] }

pub struct InfoMiddleware;

impl AfterMiddleware for InfoMiddleware {
    fn after(&self, _: &mut Request, mut response: Response) -> IronResult<Response> {
        response.headers.set(XPoweredBy("Rust/Iron/Hyper".to_owned()));
        response.headers.set(headers::Server("Transfer.rs HTTP/HTTPS Server 0.1.0".to_owned()));
        Ok(response)
    }
}
