// external use
use iron::IronResult;
use iron::request::Request as IronRequest;
use iron::response::Response as IronResponse;
use iron::{AfterMiddleware, BeforeMiddleware, Handler};
use iron::status;
use iron::headers;
use iron::modifiers;
use iron::response;
use iron::mime::{Mime, TopLevel, SubLevel};
use iron::error::{HttpError, IronError};
use router::{NoRoute, Router};
use mime_guess;
use multipart::server::{Multipart, MultipartData};
use iron::typemap::Key;

// standard use
use std::path::Path;

// intern use
use sanitize;
use storage::Storage;
use codec;

// health handler
//
pub fn health_handler(_: &mut IronRequest) -> IronResult<IronResponse> {
    Ok(IronResponse::with((status::Ok,
                           "Approaching Neutral Zone, all systems normal and functioning.")))
}

// GET handler
//
#[derive(Debug, Clone)]
pub struct GetHandler<S: Storage> {
    storage: S,
}

impl<S: Storage> GetHandler<S> {
    pub fn new(storage: S) -> Self {
        GetHandler { storage: storage }
    }
}

impl<S: Storage> Handler for GetHandler<S> {
    fn handle(&self, req: &mut IronRequest) -> IronResult<IronResponse> {
        let params = req.extensions.get::<Router>().unwrap();
        let token = &params["token"];
        let ref filename = sanitize::sanitize_filename(&params["filename"]);

        let storage_result = self.storage.get(token, filename);

        match storage_result {
            Err(ref err) => {
                if self.storage.is_not_exist(err) {
                    Ok(IronResponse::with((status::NotFound, "File not found")))
                } else {
                    error!("{}", err);
                    Ok(IronResponse::with((status::InternalServerError, "Could not retrieve file")))
                }
            }
            Ok((reader, content_type, content_length)) => {
                let mut response = IronResponse::with(status::Ok);
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
#[derive(Debug, Clone)]
pub struct PutHandler<S: Storage> {
    storage: S,
}

impl<S: Storage> PutHandler<S> {
    pub fn new(storage: S) -> Self {
        PutHandler { storage: storage }
    }
}

impl<S: Storage> Handler for PutHandler<S> {
    fn handle(&self, req: &mut IronRequest) -> IronResult<IronResponse> {
        if let Some(boundary_name) = req.extensions.get::<Boundary>().map(|b| b.name()) {
            handle_multipart_request(&self.storage, req, &boundary_name)
        } else {
            handle_put_request(&self.storage, req)
        }
    }
}

fn handle_put_request<S: Storage>(storage: &S, req: &mut IronRequest) -> IronResult<IronResponse> {
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

    let storage_result = storage.put(&token, &filename, &mut req.body);

    match storage_result {
        Err(err) => {
            error!("{}", err);
            Ok(IronResponse::with((status::InternalServerError, "Could not save file")))
        }
        Ok(_) => {
            let url_scheme = req.url.scheme();
            let msg = format!("{}://{}/{}/{}\n", url_scheme, host_address, token, filename);
            let header = modifiers::Header(headers::ContentType::plaintext());
            Ok(IronResponse::with((status::Ok, msg, header)))
        }
    }
}

fn host_to_host_address(host: &headers::Host) -> String {
    if host.port.is_none() {
        host.hostname.to_owned()
    } else {
        format!("{}:{}", host.hostname, host.port.unwrap())
    }
}

fn get_mime_from_filename(filename: &str) -> Mime {
    mime_guess::guess_mime_type(Path::new(filename))
}


// Post handler (multipart/form)
//
#[derive(Debug, Clone)]
pub struct PostHandler<S: Storage> {
    storage: S,
}

impl<S: Storage> PostHandler<S> {
    pub fn new(storage: S) -> Self {
        PostHandler { storage: storage }
    }
}

impl<S: Storage> Handler for PostHandler<S> {
    fn handle(&self, req: &mut IronRequest) -> IronResult<IronResponse> {
        let boundary = match req.extensions.get::<Boundary>() {
            Some(boundary) => boundary.name(),
            None => {
                return Ok(IronResponse::with((status::BadRequest, "Not a multipart/form request")))
            }
        };

        handle_multipart_request(&self.storage, req, &boundary)
    }
}

fn handle_multipart_request<S: Storage>(storage: &S,
                                        req: &mut IronRequest,
                                        boundary: &str)
                                        -> IronResult<IronResponse> {
    let mut multipart = Multipart::with_body(&mut req.body, boundary);
    let host_address = host_to_host_address(req.headers.get::<headers::Host>().unwrap()); // safe unwrap
    let url_scheme = req.url.scheme();
    let token = codec::random_token();

    let mut result_message = String::new();
    loop {
        match multipart.read_entry() {
            Ok(Some(multipart_field)) => {
                if let MultipartData::File(mut multipart_file) = multipart_field.data {
                    let filename = sanitize::sanitize_filename(try!(multipart_file.filename()
                        .ok_or(IronError::new(HttpError::Header,
                                              (status::BadRequest, "Filename not specified")))));

                    info!("Uploading => token: '{}', filename: '{}'", token, filename);

                    match storage.put(&token, &filename, &mut multipart_file) {
                        Ok(_) => {
                            result_message.push_str(&format!("{}://{}/{}/{}\n",
                                                             url_scheme,
                                                             host_address,
                                                             token,
                                                             filename))
                        }
                        Err(err) => return Err(IronError::new(err, status::InternalServerError)),
                    };
                }
            }
            Ok(None) => {
                return Ok(IronResponse::with((status::Ok,
                                              result_message,
                                              modifiers::Header(headers::ContentType::plaintext()))))
            }
            Err(err) => {
                error!("{}", err);
                return Err(IronError::new(err, status::InternalServerError));
            }
        }
    }
}


// MultipartMiddleware
//
pub struct MultipartMiddleware;

impl BeforeMiddleware for MultipartMiddleware {
    fn before(&self, req: &mut IronRequest) -> IronResult<()> {
        let content_type = match req.headers.get::<headers::ContentType>() {
            Some(val) => val,
            None => return Ok(()),
        };

        if let Mime(TopLevel::Multipart, SubLevel::FormData, _) = **content_type {
            if let Some(s) = content_type.get_param("boundary").map(|b| b.as_str()) {
                req.extensions.insert::<Boundary>(Boundary(s.to_owned()));
            }
        }

        Ok(())
    }
}

// Boundary
struct Boundary(String);

impl Boundary {
    fn name(&self) -> String {
        self.0.clone()
    }
}

impl Key for Boundary {
    type Value = Self;
}

// CheckHostHeaderMiddleware
//
pub struct CheckHostHeaderMiddleware;

impl BeforeMiddleware for CheckHostHeaderMiddleware {
    fn before(&self, req: &mut IronRequest) -> IronResult<()> {
        match req.headers.get::<headers::Host>() {
            Some(_) => Ok(()),
            None => {
                let modifier = (status::BadRequest, "Host header not found");
                Err(IronError::new(HttpError::Header, modifier))
            }  
        }
    }
}

// NotFoundMiddleware
//
pub struct NotFoundMiddleware;

impl AfterMiddleware for NotFoundMiddleware {
    fn catch(&self, req: &mut IronRequest, err: IronError) -> IronResult<IronResponse> {
        if let Some(_) = err.error.downcast::<NoRoute>() {
            let message = format!("why you calling {}?", req.url);
            Ok(IronResponse::with((status::NotFound, message)))
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
    fn after(&self, _: &mut IronRequest, mut response: IronResponse) -> IronResult<IronResponse> {
        response.headers.set(XPoweredBy("Rust/Iron/Hyper".to_owned()));
        response.headers.set(headers::Server("Transfer.rs HTTP/HTTPS Server 0.1.0".to_owned()));
        Ok(response)
    }
}