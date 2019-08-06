use nom::error::ErrorKind;
use pcap_parser::PcapError;
use std::convert::From;
use std::io;

#[derive(Debug)]
pub enum Error {
    Generic(&'static str),
    Nom(ErrorKind),
    IoError(io::Error),
    Pcap(PcapError),
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Error::Generic(s)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<ErrorKind> for Error {
    fn from(e: ErrorKind) -> Self {
        Error::Nom(e)
    }
}

impl From<PcapError> for Error {
    fn from(e: PcapError) -> Self {
        Error::Pcap(e)
    }
}
