use support::{
    *,
    trust_dns_proto::rr,
    trust_dns_server::{
        server,
        RequestHandler,
        ResponseHandler,
    },
    trust_dns_resolver::config::{
        NameServerConfig, ResolverConfig, Protocol,
    },
};

use std::{
    net::UdpSocket,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug)]
pub struct RecordSender(sync::mpsc::UnboundedSender<rr::Record>);

type RecordReceiver = stream::Wait<
    sync::mpsc::UnboundedReceiver<rr::Record>
>;

#[derive(Clone, Debug, Default)]
pub struct NameServer {
    expect_queries: Arc<Mutex<HashMap<rr::Name, RecordReceiver>>>,
}

pub struct Listening {
    pub addr: SocketAddr,
    shutdown: Shutdown,
}

impl Listening {
    pub fn resolver_config(&self) -> ResolverConfig {
        let name_server = NameServerConfig {
            socket_addr: self.addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
        };
        let mut resolver_cfg = ResolverConfig::new();
        resolver_cfg.add_name_server(name_server);
        resolver_cfg
    }
}


impl Stream for RecordReceiver {
    type Item = rr::Record;
    type Error = ();
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.0.poll()
    }
}

impl RecordSender {
    pub fn send(&self, up: rr::Record) {
        self.0.unbounded_send(up).expect("send DNS record update")
    }
}

impl NameServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn query_tx(&self, name: &str) -> RecordSender {
        let name = name.parse().expect("parse dns name");
        let (tx, rx) = sync::mpsc::unbounded();
        let rx = rx.wait();
        self.expect_queries
            .lock()
            .unwrap()
            .insert(name, rx);
        RecordSender(tx)
    }

    pub fn query_and_close(self, name: &str, record: rr::Record) -> Self {
        self.query_tx(name).send(record);
        self
    }

    pub fn run(self) -> Listening {
        run(self)
    }
}

impl RequestHandler for NameServer {
    fn handle_request<'q, 'a, R: ResponseHandler + 'static>(
        &'a self,
        request: &'q server::Request,
        response_handle: R
    ) -> io::Result<()> {
        for query in request.message.queries() {
            println!("DNS query: {:?}", query);
            let rx = self.expect_queries.lock()
                .unwrap()
                .get_mut(Name::from(query.name()))
                .expect("unexpected DNS name");
            let rr = rx.next()
                .expect("no more expected queries for DNS name");

            // let mut response = MessageResponse::new(Some(request.raw_queries()));
            // let mut response_header = Header::new();
            // response_header.set_id(request.id());
            // response_header.set_op_code(OpCode::Query);
            // response_header.set_message_type(MessageType::Response);
            // response_header.set_response_code(ResponseCode::NoError);
            // response_header.set_authoritative(true);
            // response.answers(records.unwrap());
        }
    }
}



fn run(nameserver: NameServer) -> Listening {
    let (tx, rx) = shutdown_signal();
    let (addr_tx, addr_rx) = oneshot::channel();
    ::std::thread::Builder::new()
        .name("support DNS nameserver".into())
        .spawn(move || {
            let addr = ([127, 0, 0, 1], 0).into();
            let bind = UdpSocket::bind(&addr).expect("bind");

            let _ = addr_tx.send(bind.local_addr().expect("addr"));
            unimplemented!()
        })
        .unwrap();
    let addr = addr_rx.wait().expect("addr");
    Listening {
        addr,
        shutdown: tx,
    }
}
