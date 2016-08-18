// Inspired by https://github.com/dutchcoders/transfer.sh
//
// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_must_use)]

// externs
//
#[macro_use]
extern crate log;
extern crate log4rs;

extern crate clap;
extern crate rand;
extern crate regex;
extern crate num_cpus;
extern crate url;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate hyper;
extern crate iron;
extern crate router;
extern crate multipart;

#[macro_use]
extern crate quick_error;
extern crate mime_guess;

extern crate openssl;

// modules
//
mod handler;
mod codec;
mod storage;
mod errors;
mod sanitize;
mod server;

// use
//

// extern
use clap::{Arg, ArgMatches, App};
use iron::Chain;
use router::Router;

use log::LogLevelFilter;
use log4rs::config::{Config, Logger, Root, Appender};
use log4rs::append::console::ConsoleAppender;
use log4rs::encode::pattern::PatternEncoder;

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;

// intern
use handler::*;
use storage::*;
use server::*;
use errors::{TransferError, Result};

fn main() {
    let temp_dir = env::temp_dir();
    let temp_dir_str = temp_dir.to_str().expect("Temp dir not found");

    if let Err(err) = init_server(match_cmd_arguments(temp_dir_str)) {
        error!("{}", err);
    }
}

fn match_cmd_arguments<'a>(temp_dir: &'a str) -> ArgMatches<'a> {
    App::new("transfer.rs")
        .version("0.1.0")
        .about("Easy file sharing from the command line")
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .value_name("PORT")
            .takes_value(true)
            .help("Sets the server port"))
        .arg(Arg::with_name("basedir")
            .short("b")
            .long("basedir")
            .value_name("BASEDIR")
            .takes_value(true)
            .default_value(temp_dir)
            .help("Sets the base directory"))
        .arg(Arg::with_name("loglevel")
            .long("loglevel")
            .value_name("LOGLEVEL")
            .takes_value(true)
            .possible_values(&["error", "warn", "info", "debug", "trace"])
            .default_value("info")
            .help("Sets the log level"))
        .arg(Arg::with_name("storage")
            .long("storage")
            .value_name("STORAGE")
            .takes_value(true)
            .possible_values(&["local"])
            .default_value("local")
            .help("Sets the storage provider"))
        .arg(Arg::with_name("ssl")
            .long("ssl")
            .requires_all(&["ssl-cert", "ssl-key"])
            .help("Enables ssl"))
        .arg(Arg::with_name("ssl-cert")
            .long("ssl-cert")
            .value_name("SSL-CERTIFICATE")
            .takes_value(true)
            .help("Sets the ssl certificate"))
        .arg(Arg::with_name("ssl-key")
            .long("ssl-key")
            .value_name("SSL-PRIVATE-KEY")
            .takes_value(true)
            .help("Sets the ssl private key"))
        .arg(Arg::with_name("ssl-cert-chain")
            .long("ssl-cert-chain")
            .value_name("SSL-CERTIFICATE-CHAIN")
            .takes_value(true)
            .help("Sets the ssl certificate chain"))
        .get_matches()
}

fn init_server(arg_matches: ArgMatches) -> Result<()> {
    let loglevel = try!(init_logger(arg_matches.value_of("loglevel")));
    let use_ssl = arg_matches.is_present("ssl");
    let port: u16 = try!(get_port(arg_matches.value_of("port"), use_ssl));
    let basedir: &str = try!(get_directory(arg_matches.value_of("basedir")));
    let storage_provider = try!(arg_matches.value_of("storage")
        .ok_or(TransferError::from("Unknown storage")));

    let addr = ("0.0.0.0", port);
    let protocol = try!(to_protocol(use_ssl,
                                    arg_matches.value_of("ssl-cert"),
                                    arg_matches.value_of("ssl-key"),
                                    arg_matches.value_of("ssl-cert-chain")));
    let chain = try!(init_chain_from_storage(storage_provider, basedir));

    info!("#####################################################");
    info!("#                    transfer.rs                    #");
    info!("#####################################################");
    info!("");
    info!("Listening on port: '{}'.", port);
    info!("Using log level: '{}'.", loglevel);
    info!("Using storage provider '{}' with base directory '{}'.",
          storage_provider,
          basedir);
    info!("Using ssl: '{}'.", use_ssl);

    try!(TransferServer::new(chain, addr, protocol)).init().unwrap();

    Ok(())
}

fn init_chain_from_storage(storage: &str, basedir: &str) -> Result<Chain> {
    match storage {
        "local" => Ok(try!(init_handler_chain(LocalStorage::new(basedir)))),
        _ => Err(TransferError::from(format!("Invalid storage '{}'", storage))),
    }
}

fn to_protocol(ssl: bool,
               ssl_cert: Option<&str>,
               ssl_key: Option<&str>,
               ssl_cert_chain: Option<&str>)
               -> Result<ExtIronProtocol> {
    if ssl {
        let cert = PathBuf::from(try!(get_directory(ssl_cert)));
        let key = PathBuf::from(try!(get_directory(ssl_key)));
        let cert_chain = if ssl_cert_chain.is_some() {
            Some(PathBuf::from(try!(get_directory(ssl_cert_chain))))
        } else {
            None
        };
        Ok(ExtIronProtocol::with_https(cert, key, cert_chain))
    } else {
        Ok(ExtIronProtocol::Http)
    }
}

fn get_port(port: Option<&str>, ssl: bool) -> Result<u16> {
    port.map(|port_str| port_str.parse::<u16>().map_err(|err| TransferError::from(err)))
        .unwrap_or_else(|| {
            if ssl {
                Ok(443u16)
            } else {
                Ok(80u16)
            }
        })
}

fn get_directory<'a>(directory: Option<&'a str>) -> Result<&'a str> {
    directory.map(|dir| {
            if Path::new(dir).exists() {
                Ok(dir)
            } else {
                Err(TransferError::from(format!("Invalid directory '{}'", dir)))
            }
        })
        .unwrap()
}

fn init_logger(log_level: Option<&str>) -> Result<LogLevelFilter> {
    let level = try!(LogLevelFilter::from_str(log_level.unwrap_or("info"))
        .map_err(|_| TransferError::from("Unknown log level")));

    // Appender
    let stdout_appender = Appender::builder()
        .build("stdout".to_owned(),
               Box::new(ConsoleAppender::builder()
                   .encoder(Box::new(PatternEncoder::new("{h({l})} {m}{n}")))
                   .build()));

    // Root logger
    let root = Root::builder().appender("stdout".to_owned()).build(level);

    // Logger
    let transerrs_logger = Logger::builder().build("transfer_rs".to_owned(), level);
    let multipart_logger = Logger::builder().build("multipart".to_owned(), LogLevelFilter::Error);

    let config = Config::builder()
        .appender(stdout_appender)
        .logger(transerrs_logger)
        .logger(multipart_logger)
        .build(root)
        .unwrap();

    log4rs::init_config(config).and(Ok(level)).map_err(|err| TransferError::from(err))
}

fn init_handler_chain<S: Storage>(storage: S) -> Result<Chain> {
    let mut router = Router::new();

    // Routes

    // ** Health handler
    router.get(r"/health.html", health_handler);

    // ** PUT upload handler
    let put_handler = PutHandler::new(storage.clone());
    router.put(r"/upload/:filename", put_handler.clone());

    // ** POST
    let post_handler = PostHandler::new(storage.clone());
    router.post(r"/upload", post_handler.clone()); // multipart/form

    // ** GET handler
    router.get(r"/download/:token/:filename",
               GetHandler::new(storage.clone()));

    // ** View handler
    let view_handler = StaticViewHandler::new();
    router.get(r"/", view_handler.clone());
    router.get(r"/:static_resource", view_handler.clone());
    router.get(r"/js/:static_resource", view_handler.clone());
    router.get(r"/css/:static_resource", view_handler.clone());

    // Chain
    let mut chain = Chain::new(router);
    chain.link_before(CheckHostHeaderMiddleware);
    chain.link_before(MultipartMiddleware);
    chain.link_after(NotFoundMiddleware);
    chain.link_after(InfoMiddleware);

    Ok(chain)
}