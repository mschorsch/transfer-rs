// Inspired by https://github.com/dutchcoders/transfer.sh
//
// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

// externs
//
#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate clap;
extern crate rand;
extern crate regex;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate hyper;

#[macro_use]
extern crate iron;

#[macro_use]
extern crate router;

#[macro_use]
extern crate quick_error;
extern crate mime_guess;

// modules
//
mod handler;
mod codec;
mod storage;
mod errors;
mod sanitize;

// use
//

// extern
use clap::{Arg, App};
use log::LogLevel;
use iron::prelude::*;
use router::Router;

use std::env;
use std::path::{Path, PathBuf};

// intern
use handler::*;
use storage::*;

fn main() {
    let temp_dir = env::temp_dir();
    let temp_dir_str = temp_dir.to_str().unwrap();

    let matches = App::new("transfer.rs")
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
            .default_value(temp_dir_str)
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
        .get_matches();

    let loglevel = matches.value_of("loglevel").unwrap(); // safe unwrap

    // Loglevel
    set_loglevel(loglevel);

    let storage_provider = matches.value_of("storage").unwrap(); //safe unwrap
    let use_ssl = matches.is_present("ssl");

    // port
    let mut port = if use_ssl {
        443u16
    } else {
        80u16
    };

    port = if matches.is_present("port") {
        match matches.value_of("port").unwrap().parse::<u16>() {
            Ok(p) => p,
            Err(err) => {
                error!("Invalid port: '{}'", err);
                return;
            }
        }
    } else {
        port
    };

    let basedir = matches.value_of("basedir").unwrap(); // save unwrap
    if !Path::new(basedir).exists() {
        error!("Invalid base directory '{}'", basedir);
        return;
    }

    // Init handler chain
    let chain = match storage_provider {
        "local" => init_handler_chain(LocalStorage::new(basedir)),
        _ => init_handler_chain(EmptyStorage),
    };

    info!("### transfer.rs server started. ###");
    info!("Listening on port: {}.", port);
    info!("Using log level: '{}'.", loglevel);
    info!("Using storage provider '{}' with base directory '{}'.",
          storage_provider,
          basedir);
    info!("Using ssl: {}.", use_ssl);

    // Start Server
    if use_ssl {
        let ssl_cert = PathBuf::from(matches.value_of("ssl-cert").unwrap());
        let ssl_key = PathBuf::from(matches.value_of("ssl-key").unwrap());
        start_server_with_ssl(chain, port, ssl_cert, ssl_key);
    } else {
        Iron::new(chain).http(("0.0.0.0", port)).unwrap();
    }

    info!("Server stopped");
}

fn set_loglevel(cmd_level: &str) {
    let level = match cmd_level {
        "error" => LogLevel::Error,
        "warn" => LogLevel::Warn,
        "info" => LogLevel::Info,
        "debug" => LogLevel::Debug,
        "trace" => LogLevel::Trace,
        _ => unreachable!("Unknown log level"),
    };

    simple_logger::init_with_level(level).unwrap();
}

fn init_handler_chain<S: Storage>(storage: S) -> Chain {
    let mut router = Router::new();

    // Routes

    // Health handler
    router.get(r"/health.html", health_handler);

    // PUT upload handler
    router.put(r"/put/:filename", PutHandler::new(storage.clone()));
    router.put(r"/upload/:filename", PutHandler::new(storage.clone()));
    router.put(r"/:filename", PutHandler::new(storage.clone()));

    // POST
    // TODO

    // Download handler
    router.get(r"/download/:token/:filename",
               GetHandler::new(storage.clone()));
    router.get(r"/:token/:filename", GetHandler::new(storage.clone()));
    router.get(r"/get/:token/:filename", GetHandler::new(storage.clone()));

    // chain
    let mut chain = Chain::new(router);
    chain.link_before(CheckHostHeaderMiddleware);
    chain.link_after(NotFoundMiddleware);
    chain.link_after(InfoMiddleware);

    chain
}

fn start_server_with_ssl(chain: Chain, port: u16, ssl_cert: PathBuf, ssl_key: PathBuf) {
    if !ssl_cert.exists() {
        error!("Ssl certificate not found.");
        return;

    } else if !ssl_key.exists() {
        error!("Ssl key not found.");
        return;
    }
    Iron::new(chain).https(("0.0.0.0", port), ssl_cert, ssl_key).unwrap();
}