use crate::runtime::ArcRuntime;
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use ipnet::IpNet;
use log::{error, info};

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
use tun::AsyncDevice;

use super::{
    nat::{Nat, Type},
    relay_tcp,
    relay_udp::UdpRelay,
};

pub async fn serve(runtime: ArcRuntime) {
    let tcp_nat = Arc::new(Nat::new(Type::Tcp));
    let udp_nat = Arc::new(Nat::new(Type::Udp));
    Gateway::new(runtime, tcp_nat, udp_nat).serve().await;
}

struct Gateway {
    runtime: ArcRuntime,
    gateway: Ipv4Addr,
    network: IpNet,
    tcp_nat: Arc<Nat>,
    udp_nat: Arc<Nat>,
    relay_port: u16,
    udp_relay: Arc<UdpRelay>,
}

impl Gateway {
    fn new(runtime: ArcRuntime, tcp_nat: Arc<Nat>, udp_nat: Arc<Nat>) -> Self {
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

        // Create UDP relay instance once and reuse
        let udp_relay = Arc::new(UdpRelay::new(runtime.clone(), udp_nat.clone()));

        Self {
            runtime,
            gateway,
            network,
            tcp_nat,
            udp_nat,
            relay_port,
            udp_relay,
        }
    }

    async fn serve(&self) {
        let dev = self.setup().await;

        let mut stream = dev.into_framed();

        while let Some(packet) = stream.next().await {
            if let Ok(packet) = packet {
                let mut packet = packet;
                let mut v4 = ipv4::MutableIpv4Packet::new(&mut packet).unwrap();
                let src = v4.get_source();
                let dst = v4.get_destination();
                let protocol = v4.get_next_level_protocol();

                let data = match protocol {
                    IpNextHeaderProtocols::Icmp => self.handle_icmp_v4(&mut v4).await,
                    IpNextHeaderProtocols::Udp => self.handle_udp_v4(&mut v4).await,
                    IpNextHeaderProtocols::Tcp => self.handle_tcp_v4(&mut v4).await,
                    _ => None,
                };

                if let Some(data) = data
                    && let Err(e) = stream.send(data).await
                {
                    error!(
                        "send reply error: {:?}, src: {}, dst:{}, protocol: {:?}",
                        e, src, dst, protocol
                    );
                }
            }
        }
    }

    async fn setup(&self) -> AsyncDevice {
        info!("gateway addr: {}", self.network.addr());
        let mut config = tun::Configuration::default();
        config
            .layer(tun::Layer::L3)
            .address(self.network.addr())
            .destination(self.gateway)
            .netmask(self.network.netmask())
            .up();

        #[cfg(target_os = "linux")]
        {
            config.tun_name("kf0");
        }

        let dev = match tun::create_as_async(&config) {
            Ok(dev) => dev,
            Err(e) => {
                error!("create tun failed, err: {:?}", e);
                process::exit(1);
            }
        };

        let gateway = &self.gateway.to_string();
        let network = &format!("{}/{}", self.network.network(), self.network.prefix_len());

        #[cfg(target_os = "macos")]
        {
            use log::debug;
            use std::thread::sleep;
            use std::time::Duration;
            // wait dev setup
            sleep(Duration::from_millis(200));
            debug!("for macOS manual add net route {}", network);

            let _ = Command::new("route")
                .args(["-n", "-q", "add", "-net", network, gateway])
                .output();

            let _ = Command::new("networksetup")
                .args(["-setdnsservers", "Wi-Fi", "127.0.0.1"])
                .output();
        }

        #[cfg(target_os = "macos")]
        tokio::spawn(async {
            use tokio::signal;
            if let Ok(_) = signal::ctrl_c().await {
                let _ = Command::new("networksetup")
                    .args(["-setdnsservers", "Wi-Fi", "empty"])
                    .output();
                process::exit(0);
            }
        });

        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("ip")
                .args(["route", "add", network, "via", gateway])
                .output();
        }

        let routes = self.runtime.rules.get_route_rules();

        for r in routes {
            #[cfg(target_os = "linux")]
            {
                let _ = Command::new("ip")
                    .args(["route", "add", &r, "via", gateway])
                    .output();
            }

            #[cfg(target_os = "macos")]
            {
                let _ = Command::new("route")
                    .args(["-n", "-q", "add", "-net", &r, gateway])
                    .output();
            }
        }

        // setup tcp forward
        self.setup_tcp_relay().await;

        dev
    }

    async fn setup_tcp_relay(&self) {
        let addr = format!("{}:{}", self.network.addr(), self.relay_port);
        let relay = relay_tcp::Relay::new(self.runtime.clone(), addr, self.tcp_nat.clone());
        relay.serve().await
    }

    async fn handle_icmp_v4(&self, v4: &mut MutableIpv4Packet<'_>) -> Option<Vec<u8>> {
        let mut payload = v4.payload().to_vec();
        let mut packet = MutableIcmpPacket::new(&mut payload).unwrap();

        if packet.get_icmp_type() == IcmpTypes::EchoRequest {
            packet.set_icmp_type(IcmpTypes::EchoReply);
            packet.set_checksum(icmp::checksum(&packet.to_immutable()))
        }

        let src = v4.get_source();
        let dst = v4.get_destination();

        v4.set_destination(src);
        v4.set_source(dst);
        v4.set_payload(&payload);
        v4.set_checksum(ipv4::checksum(&v4.to_immutable()));

        Some(v4.packet().to_vec())
    }

    async fn handle_udp_v4(&self, v4: &mut MutableIpv4Packet<'_>) -> Option<Vec<u8>> {
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

            return Some(p.packet().to_vec());
        }

        // Check if this is a packet that should be proxied
        if !self.network.hosts().any(|v| v == dst) {
            return None;
        }

        // Create UDP session
        let session = self.udp_nat.create(src, src_port, dst, dst_port);

        // Extract UDP payload
        let udp_payload = packet.payload();

        // Handle packet with reusable UDP relay
        match self.udp_relay.handle_packet(session, udp_payload).await {
            Ok(Some(response_data)) => {
                // Build response UDP packet
                let response_len = response_data.len();
                let udp_total_len = 8 + response_len; // UDP header + data
                let mut udp_buf = BytesMut::zeroed(udp_total_len);
                let mut udp_packet = MutableUdpPacket::new(&mut udp_buf).unwrap();

                udp_packet.set_source(dst_port);
                udp_packet.set_destination(src_port);
                udp_packet.set_length(udp_total_len as u16);
                udp_packet.set_payload(&response_data);
                udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(
                    &udp_packet.to_immutable(),
                    &dst,
                    &src,
                ));

                // Build IP packet
                let ip_total_len = v4.get_header_length() as usize * 4 + udp_total_len;
                let mut ip_buf = BytesMut::zeroed(ip_total_len);
                let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf).unwrap();

                ip_packet.set_version(4);
                ip_packet.set_header_length(v4.get_header_length());
                ip_packet.set_total_length(ip_total_len as u16);
                ip_packet.set_source(dst);
                ip_packet.set_destination(src);
                ip_packet.set_ttl(64);
                ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                ip_packet.set_payload(udp_packet.packet());
                ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

                Some(ip_packet.packet().to_vec())
            }
            Ok(None) => {
                // No response (normal for UDP)
                None
            }
            Err(e) => {
                error!("UDP relay error: {}", e);
                None
            }
        }
    }

    async fn handle_tcp_v4(&self, v4: &mut MutableIpv4Packet<'_>) -> Option<Vec<u8>> {
        let mut payload = v4.payload().to_vec();
        let mut packet = MutableTcpPacket::new(&mut payload).unwrap();

        let src = v4.get_source();
        let dst = v4.get_destination();
        let src_port = packet.get_source();
        let dst_port = packet.get_destination();

        let nat = self.tcp_nat.clone();

        if src_port == self.relay_port && self.network.addr() == src {
            let session = nat.find(dst_port);
            let session = session.as_ref()?;

            packet.set_source(session.dst_port);
            packet.set_destination(session.src_port);

            v4.set_source(session.dst_addr);
            v4.set_destination(session.src_addr);
        } else {
            let session = nat.create(src, src_port, dst, dst_port);

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

        Some(v4.packet().to_vec())
    }
}
