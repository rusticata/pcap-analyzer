use pcap_parser::nom::Needed;
use pcap_parser::nom::{error::ErrorKind, Err};
use pcap_parser::PcapError;
use std::convert::From;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Internal parser error {0:?}")]
    Nom(ErrorKind),
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("Pcap parser error {0:?}")]
    Pcap(#[from] PcapError<&'static [u8]>),
    #[error("Pnet error {0}")]
    Pnet(&'static str),
    #[error("Data parser error {0}")]
    DataParser(&'static str),
    #[error("Unimplemented error {0}")]
    Unimplemented(&'static str),
    #[error("Unsupported error {0}")]
    Unsupported(&'static str),
    #[error("Generic error {0}")]
    Generic(&'static str),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Generic(s)
    }
}

impl From<ErrorKind> for Error {
    fn from(e: ErrorKind) -> Self {
        Error::Nom(e)
    }
}

impl<'a> From<Err<PcapError<&'a [u8]>>> for Error {
    fn from(err: Err<PcapError<&'a [u8]>>) -> Self {
        match err {
            Err::Incomplete(needed) => {
                let sz = if let Needed::Size(sz) = needed {
                    usize::from(sz)
                } else {
                    0
                };
                Error::Pcap(PcapError::Incomplete(sz))
            }
            Err::Error(e) | Err::Failure(e) => Error::Pcap(e.to_owned_vec()),
        }
    }
}
