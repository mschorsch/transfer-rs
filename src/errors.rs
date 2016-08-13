use std::io;
use std::result;
use log;
use std::num;

pub type Result<T> = result::Result<T, TransferError>;

quick_error! {

    #[derive(Debug)]
    pub enum TransferError {
        
        Io(err: io::Error) {
            cause(err)
            description(err.description())
            from()
        }

        Log(err: log::SetLoggerError) {
            cause(err)
            description(err.description())
            from()
        }

        ParseInt(err: num::ParseIntError) {
            cause(err)
            description(err.description())
            from()
        }

        Msg(s: String) {
            description(s)
            display("{}", s)
            from()
            from(s: &'static str) -> (s.to_owned())
        }

        #[allow(dead_code)]
        StaticMsg(msg: &'static str) {
            description(msg)
            display("{}", msg)            
        }
    }    
}