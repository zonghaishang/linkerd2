use bytes::Buf;
use futures::{Async, Future, Poll};
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use tokio_connect;
use tokio::io::{AsyncRead, AsyncWrite};
use rustls;

use connection::Peek;
use ctx;
use telemetry::event;

/// Wraps a transport with telemetry.
#[derive(Debug)]
pub struct Transport<T>(T, Option<Inner>);

#[derive(Debug)]
struct Inner {
    handle: super::Handle,
    ctx: Arc<ctx::transport::Ctx>,
    opened_at: Instant,

    rx_bytes: u64,
    tx_bytes: u64,
}

/// Builds client transports with telemetry.
#[derive(Clone, Debug)]
pub struct Connect<C> {
    underlying: C,
    handle: super::Handle,
    ctx: Arc<ctx::transport::Client>,
}

/// Adds telemetry to a pending client transport.
#[derive(Clone, Debug)]
pub struct Connecting<C: tokio_connect::Connect> {
    underlying: C::Future,
    handle: super::Handle,
    ctx: Arc<ctx::transport::Client>,
}

#[derive(Clone, Debug)]
pub struct Tls {
    handle: super::Handle,
    ctx: Arc<ctx::Proxy>,
}

/// Adds telemetry to a TLS handshake.
#[derive(Clone, Debug)]
pub struct Handshake<F: Future<Error = io::Error>> {
    inner: F,
    handle: super::Handle,
    ctx: Arc<ctx::transport::Ctx>,
}

// === impl Transport ===

impl<T: AsyncRead + AsyncWrite> Transport<T> {
    /// Wraps a transport with telemetry and emits a transport open event.
    pub(super) fn open(
        io: T,
        opened_at: Instant,
        handle: &super::Handle,
        ctx: Arc<ctx::transport::Ctx>,
    ) -> Self {
        let mut handle = handle.clone();

        handle.send(|| event::Event::TransportOpen(Arc::clone(&ctx)));

        Transport(
            io,
            Some(Inner {
                ctx,
                handle,
                opened_at,
                rx_bytes: 0,
                tx_bytes: 0,
            }),
        )
    }

    /// Wraps an operation on the underlying transport with error telemetry.
    ///
    /// If the transport operation results in a non-recoverable error, a transport close
    /// event is emitted.
    fn sense_err<F, U>(&mut self, op: F) -> io::Result<U>
    where
        F: FnOnce(&mut T) -> io::Result<U>,
    {
        match op(&mut self.0) {
            Ok(v) => Ok(v),
            Err(e) => {
                if e.kind() != io::ErrorKind::WouldBlock {
                    if let Some(Inner {
                        mut handle,
                        ctx,
                        opened_at,
                        rx_bytes,
                        tx_bytes,
                    }) = self.1.take()
                    {
                        handle.send(move || {
                            let duration = opened_at.elapsed();
                            let ev = event::TransportClose {
                                duration,
                                clean: false,
                                rx_bytes,
                                tx_bytes,
                            };
                            event::Event::TransportClose(ctx, ev)
                        });
                    }
                }

                Err(e)
            }
        }
    }
}

impl<T> Drop for Transport<T> {
    fn drop(&mut self) {
        if let Some(Inner {
            mut handle,
            ctx,
            opened_at,
            rx_bytes,
            tx_bytes,
        }) = self.1.take()
        {
            handle.send(move || {
                let duration = opened_at.elapsed();
                let ev = event::TransportClose {
                    clean: true,
                    duration,
                    rx_bytes,
                    tx_bytes,
                };
                event::Event::TransportClose(ctx, ev)
            });
        }
    }
}

impl<T: AsyncRead + AsyncWrite> io::Read for Transport<T> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.sense_err(move |io| io.read(buf))?;

        if let Some(inner) = self.1.as_mut() {
            inner.rx_bytes += bytes as u64;
        }

        Ok(bytes)
    }
}

impl<T: AsyncRead + AsyncWrite> io::Write for Transport<T> {
    fn flush(&mut self) -> io::Result<()> {
        self.sense_err(|io| io.flush())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.sense_err(move |io| io.write(buf))?;

        if let Some(inner) = self.1.as_mut() {
            inner.tx_bytes += bytes as u64;
        }

        Ok(bytes)
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncRead for Transport<T> {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        self.0.prepare_uninitialized_buffer(buf)
    }
}

impl<T: AsyncRead + AsyncWrite> AsyncWrite for Transport<T> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.sense_err(|io| io.shutdown())
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        let bytes = try_ready!(self.sense_err(|io| io.write_buf(buf)));

        if let Some(inner) = self.1.as_mut() {
            inner.tx_bytes += bytes as u64;
        }

        Ok(Async::Ready(bytes))
    }
}

impl<T: AsyncRead + AsyncWrite + Peek> Peek for Transport<T> {
    fn poll_peek(&mut self) -> Poll<usize, io::Error> {
        self.sense_err(|io| io.poll_peek())
    }

    fn peeked(&self) -> &[u8] {
        self.0.peeked()
    }
}

// === impl Connect ===

impl<C: tokio_connect::Connect> Connect<C> {
    /// Returns a `Connect` to `addr` and `handle`.
    pub(super) fn new(
        underlying: C,
        handle: &super::Handle,
        ctx: &Arc<ctx::transport::Client>,
    ) -> Self {
        Connect {
            underlying,
            handle: handle.clone(),
            ctx: Arc::clone(ctx),
        }
    }
}

impl<C: tokio_connect::Connect> tokio_connect::Connect for Connect<C> {
    type Connected = Transport<C::Connected>;
    type Error = C::Error;
    type Future = Connecting<C>;

    fn connect(&self) -> Self::Future {
        Connecting {
            underlying: self.underlying.connect(),
            handle: self.handle.clone(),
            ctx: Arc::clone(&self.ctx),
        }
    }
}

// === impl Connecting ===

impl<C: tokio_connect::Connect> Future for Connecting<C> {
    type Item = Transport<C::Connected>;
    type Error = C::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let io = try_ready!(self.underlying.poll());
        debug!("client connection open");
        let ctx = Arc::new(Arc::clone(&self.ctx).into());
        let trans = Transport::open(io, Instant::now(), &self.handle, ctx);
        Ok(trans.into())
    }
}

// === impl Tls ===

impl Tls {
    pub(super) fn new(
        handle: &super::Handle,
        ctx: &Arc<ctx::Proxy>,
    ) -> Self {
        Tls {
            handle: handle.clone(),
            ctx: Arc::clone(ctx)
        }
    }

    pub fn accept_handshake<F>(
        &self,
        inner: F,
        local: &SocketAddr,
        remote: &SocketAddr,
    ) -> Handshake<F>
    where
        F : Future<Error = io::Error>,
    {
        let ctx = ctx::transport::Server::new(
            &self.ctx,
            &local,
            &remote,
            &None,
            // This context will *only* be used if handshaking fails, so it's
            // okay to pre-set this.
            ctx::transport::TlsStatus::HandshakeError,
        );
        Handshake {
            inner,
            handle: self.handle.clone(),
            ctx: Arc::new(ctx.into()),
        }
    }
}

// === impl Handshake ===

impl<F: Future<Error = io::Error>> Future for Handshake<F> {
    type Item = F::Item;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.inner.poll() {
            ok @ Ok(_) => ok,
            Err(e) => {
                if let Some(tls_error) = e
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<rustls::TLSError>())
                {
                    let ctx = self.ctx.clone();
                    self.handle.send(||
                        event::Event::TlsHandshakeFail(
                            ctx,
                            tls_error.clone(),
                        )
                    );
                }
                Err(e)
            }
        }

    }
}
