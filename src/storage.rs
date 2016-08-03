use std::io;
use std::path::Path;
use std::fs;
use mime_guess::{guess_mime_type, get_mime_type};
use iron::mime::Mime;

use errors::*;

pub trait Storage<OR: io::Read>: Clone + Send + Sync + 'static {
    fn get(&self, token: &str, filename: &str) -> Result<(OR, Mime, u64)>;

    fn head(&self, token: &str, filename: &str) -> Result<(Mime, u64)>;

    fn put<IR: io::Read>(&self,
                         token: &str,
                         filename: &str,
                         reader: &mut IR,
                         content_type: &Mime,
                         content_length: u64)
                         -> Result<()>;

    fn is_not_exist(&self, err: &TransferError) -> bool;
}

#[derive(Debug, Clone)]
pub struct EmptyStorage;

impl Storage<io::Empty> for EmptyStorage {
    fn get(&self, _: &str, filename: &str) -> Result<(io::Empty, Mime, u64)> {
        Ok((io::empty(), get_mime_type(filename), 0))
    }

    fn head(&self, _: &str, filename: &str) -> Result<(Mime, u64)> {
        Ok((get_mime_type(filename), 0))
    }

    fn put<IR: io::Read>(&self, _: &str, _: &str, _: &mut IR, _: &Mime, _: u64) -> Result<()> {
        Ok(())
    }

    fn is_not_exist(&self, _: &TransferError) -> bool {
        false
    }
}

#[derive(Debug, Clone)]
pub struct LocalStorage {
    base_dir: String,
}

impl LocalStorage {
    pub fn new<S: Into<String>>(base_dir: S) -> Self {
        LocalStorage { base_dir: base_dir.into() }
    }
}

impl Storage<fs::File> for LocalStorage {
    fn get(&self, token: &str, filename: &str) -> Result<(fs::File, Mime, u64)> {
        let path = Path::new(&self.base_dir).join(token).join(filename);

        let file: fs::File = try!(fs::File::open(&path));
        let mime = guess_mime_type(&path);
        let content_length: u64 = try!(file.metadata()).len();

        Ok((file, mime, content_length))
    }

    fn head(&self, token: &str, filename: &str) -> Result<(Mime, u64)> {
        let path = Path::new(&self.base_dir).join(token).join(filename);

        let mime = guess_mime_type(&path);
        let content_length: u64 = try!(fs::metadata(&path)).len();

        Ok((mime, content_length))
    }

    fn put<R: io::Read>(&self,
                        token: &str,
                        filename: &str,
                        reader: &mut R,
                        _: &Mime,
                        _: u64)
                        -> Result<()> {
        let dir_path = Path::new(&self.base_dir).join(token);

        if !dir_path.exists() {
            try!(fs::create_dir(&dir_path));
        }

        let file_path = dir_path.join(filename);
        let mut file = try!(fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path));

        try!(io::copy(reader, &mut file).map_err(|_| "couldn't copy file data to storage"));

        Ok(())
    }

    fn is_not_exist(&self, err: &TransferError) -> bool {
        match err {
            &TransferError::Io(ref io_err) => io_err.kind() == io::ErrorKind::NotFound,
            _ => false, 
        }
    }
}