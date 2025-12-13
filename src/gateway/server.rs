use crate::{gateway::relay_tcp::TcpRelay, runtime::ArcRuntime};
use bytes::{Bytes, BytesMut};
use ipnet::IpNet;
use log::{debug, error, info};

use pnet::packet::{
    Packet,
    icmp::{self, IcmpTypes, MutableIcmpPacket, destination_unreachable::IcmpCodes},
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket},
    udp::MutableUdpPacket,
};
use std::{
    net::Ipv4Addr,
    process::{self, Command},
    str::FromStr,
    sync::Arc,
};
use tokio::{join, sync::mpsc::{self, UnboundedSender}};
use tun_rs::{AsyncDevice, DeviceBuilder};

use super::{
    nat::{Nat, Type},
    relay_udp::UdpRelay,
};

pub async fn serve(runtime: ArcRuntime) {
    Gateway::new(runtime).serve().await;
}

struct Gateway {
    runtime: ArcRuntime,
    gateway: Ipv4Addr,
    network: IpNet,
    tcp_nat: Arc<Nat>,
    udp_nat: Arc<Nat>,
    relay_port: u16,
    tcp_relay: TcpRelay,
    udp_relay: UdpRelay,
}

impl Gateway {
    fn new(runtime: ArcRuntime) -> Self {
        let network =
            IpNet::from_str(&runtime.setting.network).expect("Invalid network configuration");
        let gateway = match network {
            IpNet::V4(v) => v.addr(),
            IpNet::V6(_) => panic!("IPv6 not supported yet"),
        };

        let relay_port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("Failed to bind to random port")
            .local_addr()
            .expect("Failed to get local address")
            .port();

        let (tx, rx) = mpsc::channel(1);
        let tcp_nat = Arc::new(Nat::new(Type::Tcp, None));
        let udp_nat = Arc::new(Nat::new(Type::Udp, Some(tx)));
        let udp_relay = UdpRelay::new(runtime.clone(), rx);
        let tcp_relay = TcpRelay::new(
            runtime.clone(),
            format!("{}:{}", network.addr(), relay_port),
            tcp_nat.clone(),
        );

        Self {
            runtime,
            gateway,
            network,
            tcp_nat,
            udp_nat,
            relay_port,
            tcp_relay,
            udp_relay,
        }
    }

    async fn serve(&self) {
        let dev = Arc::new(self.setup().await);
        let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<Bytes>();

        let write_task = async {
            let dev = dev.clone();
            while let Some(packet) = packet_rx.recv().await {
                let _ = dev.send(&packet).await;
            }
        };

        let handle_task = async {
            let dev = dev.clone();
            let mut buf = BytesMut::zeroed(65536);
            while let Ok(len) = dev.clone().recv(&mut buf).await {
                let packet_tx = packet_tx.clone();
                let mut ipv4 = ipv4::MutableIpv4Packet::new(&mut buf[..len]).unwrap();
                let protocol = ipv4.get_next_level_protocol();
                match protocol {
                    IpNextHeaderProtocols::Icmp => self.handle_icmp_v4(packet_tx, &mut ipv4).await,
                    IpNextHeaderProtocols::Udp => self.handle_udp_v4(packet_tx, &mut ipv4).await,
                    IpNextHeaderProtocols::Tcp => self.handle_tcp_v4(packet_tx, &mut ipv4).await,
                    _ => {}
                };
            }
        };

        join!(write_task, handle_task);
    }

    async fn setup(&self) -> AsyncDevice {
        info!("gateway addr: {}", self.network.addr());

        let mut builder = DeviceBuilder::new();

        // Configure IPv4 address and netmask
        let addr_str = self.network.addr().to_string();
        let prefix_len = self.network.prefix_len();
        builder = builder.ipv4(addr_str, prefix_len, None);
        builder = builder.mtu(1500);

        #[cfg(target_os = "linux")]
        {
            builder = builder.name("kf0");
            builder = builder.tx_queue_len(1000);
        }

        let dev = match builder.build_async() {
            Ok(dev) => dev,
            Err(e) => {
                error!("create tun failed, err: {:?}", e);
                process::exit(1);
            }
        };

        let gateway = &self.gateway.to_string();

        #[cfg(target_os = "macos")]
        {
            use std::thread::sleep;
            use std::time::Duration;

            // wait dev setup
            sleep(Duration::from_millis(200));

            let network = &format!("{}/{}", self.network.network(), self.network.prefix_len());

            let _ = Command::new("route")
                .args(["-n", "-q", "add", "-net", network, gateway])
                .output();

            let _ = Command::new("networksetup")
                .args(["-setdnsservers", "Wi-Fi", "127.0.0.1"])
                .output();

            tokio::spawn(async {
                use tokio::signal;
                if let Ok(_) = signal::ctrl_c().await {
                    let _ = Command::new("networksetup")
                        .args(["-setdnsservers", "Wi-Fi", "empty"])
                        .output();
                    process::exit(0);
                }
            });
        }

        let routes = self.runtime.rules.get_route_rules();

        for r in routes {
            #[cfg(target_os = "linux")]
            {
                if let Err(e) = Command::new("ip")
                    .args(["route", "add", &r, "via", gateway])
                    .output()
                {
                    error!("add route {} via {} failed, err: {:?}", r, gateway, e);
                }
            }

            #[cfg(target_os = "macos")]
            {
                let _ = Command::new("route")
                    .args(["-n", "-q", "add", "-net", &r, gateway])
                    .output();
            }
        }

        self.setup_tcp_relay().await;

        dev
    }

    async fn setup_tcp_relay(&self) {
        if let Err(e) = self.tcp_relay.serve().await {
            log::error!("TCP relay server error: {}", e);
        }
    }

    async fn handle_icmp_v4(
        &self,
        packet_tx: UnboundedSender<Bytes>,
        v4: &mut MutableIpv4Packet<'_>,
    ) {
        let src = v4.get_source();
        let dst = v4.get_destination();
        let ttl = v4.get_ttl();

        let mut payload_vec = v4.payload().to_vec();
        let mut packet = MutableIcmpPacket::new(&mut payload_vec).unwrap();
        let icmp_type = packet.get_icmp_type();

        let is_hijacked = self.network.hosts().any(|v| v == dst);

        // Similar to UDP traceroute handling, if this is an Echo Request
        // to a hijacked domain with low TTL, return a response
        if icmp_type == IcmpTypes::EchoRequest && is_hijacked && ttl < 5 {
            // For mtr/traceroute, we want to simulate reaching the destination
            // by responding with Echo Reply directly
            packet.set_icmp_type(IcmpTypes::EchoReply);
            packet.set_checksum(icmp::checksum(&packet.to_immutable()));

            v4.set_destination(src);
            v4.set_source(dst); // Simulating the target
            v4.set_ttl(64);
            v4.set_payload(&payload_vec);
            v4.set_checksum(ipv4::checksum(&v4.to_immutable()));

            let _ = packet_tx.send(Bytes::copy_from_slice(v4.packet()));
            return;
        }

        // Handle normal ICMP packet
        match icmp_type {
            // Echo Request -> Echo Reply (ping)
            IcmpTypes::EchoRequest => {
                packet.set_icmp_type(IcmpTypes::EchoReply);
                packet.set_checksum(icmp::checksum(&packet.to_immutable()));

                v4.set_destination(src);
                v4.set_source(dst); // Simulate the target responding
                v4.set_ttl(64);
                v4.set_payload(&payload_vec);
                v4.set_checksum(ipv4::checksum(&v4.to_immutable()));

                let _ = packet_tx.send(Bytes::copy_from_slice(v4.packet()));
            }
            _ => {
                debug!("Ignoring ICMP type: {:?}", icmp_type);
            }
        }
    }

    async fn handle_udp_v4(
        &self,
        packet_tx: UnboundedSender<Bytes>,
        v4: &mut MutableIpv4Packet<'_>,
    ) {
        let mut payload = v4.payload().to_vec();
        let packet = MutableUdpPacket::new(&mut payload).unwrap();

        let src = v4.get_source();
        let dst = v4.get_destination();
        let ttl = v4.get_ttl();
        let src_port = packet.get_source();
        let dst_port = packet.get_destination();

        // trace route
        if dst_port >= 33000 && ttl < 5 && self.network.hosts().any(|v| v == dst) {
            let mut buf = BytesMut::zeroed(8 + v4.get_total_length() as usize);
            let mut p = MutableIcmpPacket::new(&mut buf).unwrap();

            // ICMP wrap IP packet
            p.set_icmp_type(IcmpTypes::DestinationUnreachable);
            p.set_icmp_code(IcmpCodes::DestinationPortUnreachable);
            let mut payload = BytesMut::new();
            payload.extend(vec![0u8; 4]);
            payload.extend(v4.packet());
            p.set_payload(&payload);
            p.set_checksum(icmp::checksum(&p.to_immutable()));

            // build ip packet

            let payload = p.packet();
            let total_len = v4.get_header_length() as usize * 4 + payload.len();

            let mut buf = BytesMut::zeroed(total_len);

            let mut p = MutableIpv4Packet::new(&mut buf).unwrap();
            p.set_version(4);
            p.set_header_length(v4.get_header_length());
            p.set_total_length(total_len.try_into().unwrap());
            p.set_source(dst);
            p.set_destination(src);
            p.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            p.set_ttl(64);
            p.set_payload(payload);
            p.set_checksum(ipv4::checksum(&p.to_immutable()));

            let _ = packet_tx.send(Bytes::copy_from_slice(p.packet()));
        }

        let session = self.udp_nat.create(src, src_port, dst, dst_port).await;

        let udp_payload = packet.payload();

        let ip_header_length = v4.get_header_length();
        let callback = move |data: Bytes| {
            let packet_tx = packet_tx.clone();
            let dst = dst;
            let src = src;
            let dst_port = dst_port;
            let src_port = src_port;
            let ip_header_length = ip_header_length;
            async move {
                // Build response UDP packet
                let response_len = data.len();
                let udp_total_len = 8 + response_len; // UDP header + data
                let mut udp_buf = BytesMut::zeroed(udp_total_len);
                let mut udp_packet = MutableUdpPacket::new(&mut udp_buf).unwrap();

                udp_packet.set_source(dst_port);
                udp_packet.set_destination(src_port);
                udp_packet.set_length(udp_total_len as u16);
                udp_packet.set_payload(&data);
                udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(
                    &udp_packet.to_immutable(),
                    &dst,
                    &src,
                ));

                // Build IP packet
                let ip_total_len = ip_header_length as usize * 4 + udp_total_len;
                let mut ip_buf = BytesMut::zeroed(ip_total_len);
                let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();

                ip_packet.set_version(4);
                ip_packet.set_header_length(ip_header_length);
                ip_packet.set_total_length(ip_total_len as u16);
                ip_packet.set_source(dst);
                ip_packet.set_destination(src);
                ip_packet.set_ttl(64);
                ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                ip_packet.set_payload(udp_packet.packet());
                ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

                let _ = packet_tx.send(Bytes::copy_from_slice(ip_packet.packet()));
            }
        };

        let _ = self.udp_relay.send(session, udp_payload, callback).await;
    }

    async fn handle_tcp_v4(
        &self,
        packet_tx: UnboundedSender<Bytes>,
        v4: &mut MutableIpv4Packet<'_>,
    ) {
        let mut payload = v4.payload().to_vec();
        let mut packet = MutableTcpPacket::new(&mut payload).unwrap();

        let src = v4.get_source();
        let dst = v4.get_destination();
        let src_port = packet.get_source();
        let dst_port = packet.get_destination();

        let nat = self.tcp_nat.clone();

        if src_port == self.relay_port && self.network.addr() == src {
            let session = nat.find(dst_port).await;
            match session {
                None => {
                    return;
                }
                Some(ref session) => {
                    packet.set_source(session.dst_port);
                    packet.set_destination(session.src_port);

                    v4.set_source(session.dst_addr);
                    v4.set_destination(session.src_addr);
                }
            }
        } else {
            let session = nat.create(src, src_port, dst, dst_port).await;

            packet.set_source(session.nat_port);
            packet.set_destination(self.relay_port);

            v4.set_source(dst);
            v4.set_destination(self.gateway);
        }

        packet.set_checksum(tcp::ipv4_checksum(
            &packet.to_immutable(),
            &v4.get_source(),
            &v4.get_destination(),
        ));

        v4.set_payload(packet.packet());
        v4.set_checksum(ipv4::checksum(&v4.to_immutable()));

        let _ = packet_tx.send(Bytes::copy_from_slice(v4.packet()));
    }
}
