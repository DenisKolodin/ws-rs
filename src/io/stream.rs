use std::io;
use std::mem::swap;

use openssl::ssl::{SslStream, SslContext};
use mio::tcp::TcpStream;

use connection::factory::Factory;
use result::{Result, Error, Kind};

fn to_ssl_non_block(err: Error) -> Result<Option<SslStream<TcpStream>>> {
    if let Kind::Io(ioerr) = err.kind {
        match ioerr.kind() {
            io::ErrorKind::WouldBlock => return Ok(None),
            _ => Err(Error::new(Kind::Io(ioerr), err.details)),
        }
    } else {
        Err(err)
    }
}

use self::Stream::*;
#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    TlsConnecting(TcpStream),
    TlsEstablished(SslStream<TcpStream>),
}

impl Stream {

    pub fn evented(&self) -> &TcpStream {
        match *self {
            Tcp(ref stream) => stream,
            TlsConnecting(ref stream) => stream,
            TlsEstablished(ref ssl) => ssl.get_ref(),
        }
    }

    pub fn upgrade<F>(&mut self, factory: &mut F, is_client: bool) -> Result<Option<()>>
        where F: Factory
    {
        if let TlsConnecting(_) = *self {
            let sock = try!(self.evented().try_clone());
            let context = try!(factory.ssl_context());

            debug!("Attempting to upgrade connection to TLS.");
            if is_client {
                if let Some(ssl) = try!(
                    SslStream::connect(&context, sock)
                        .map(|ssl| Some(ssl))
                        .map_err(Error::from)
                        .or_else(to_ssl_non_block))
                {
                    swap(self, &mut TlsEstablished(ssl));
                    return Ok(Some(()))
                }
            } else {
                unimplemented!();
            }
            return Ok(None)
        }
        Ok(Some(()))
    }
}

impl io::Read for Stream {

    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            Tcp(ref mut s) => s.read(buf),
            TlsConnecting(ref mut s) => s.read(buf),
            TlsEstablished(ref mut s) => s.read(buf),
        }
    }
}

impl io::Write for Stream {

    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            Tcp(ref mut s) => s.write(buf),
            TlsConnecting(ref mut s) => s.write(buf),
            TlsEstablished(ref mut s) => s.write(buf),
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {

        match *self {
            Tcp(ref mut s) => s.flush(),
            TlsConnecting(ref mut s) => s.flush(),
            TlsEstablished(ref mut s) => s.flush(),
        }
    }
}

