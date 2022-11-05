use crate::config::{setting::RuleType, ArcSetting};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use ipnet::IpNet;
use log::{error, info};

use pnet::packet::{
    icmp::{self, destination_unreachable::IcmpCodes, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket},
    udp::MutableUdpPacket,
    Packet,
};
use std::{
    net::Ipv4Addr,
    process::{self, Command},
    str::FromStr,
    sync::Arc,
};
use tun::{AsyncDevice, TunPacket};

use super::{
    nat::{Nat, Type},
    relay_tcp,
};

pub async fn serve(setting: ArcSetting) {
    let tcp_nat = Arc::new(Nat::new(Type::Tcp));
    Gateway::new(setting, tcp_nat).serve().await;
}

struct Gateway {
    setting: ArcSetting,
    gateway: Ipv4Addr,
    network: IpNet,
    tcp_nat: Arc<Nat>,
    relay_port: u16,
}

impl Gateway {
    fn new(setting: ArcSetting, tcp_nat: Arc<Nat>) -> Self {
        let network = IpNet::from_str(&setting.network).unwrap();
        let gateway = match network {
            IpNet::V4(v) => v.addr(),
            IpNet::V6(_) => panic!("not supported yet"),
        };

        let relay_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        Self {
            setting,
            gateway,
            network,
            tcp_nat,
            relay_port,
        }
    }

    async fn serve(&self) {
        let dev = self.setup().await;

        let mut stream = dev.into_framed();

        while let Some(packet) = stream.next().await {
            if let Ok(packet) = packet {
                let mut packet = packet.get_bytes().to_vec();
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

                if let Some(data) = data {
                    if let Err(e) = stream.send(TunPacket::new(data)).await {
                        error!(
                            "send reply error: {:?}, src: {}, dst:{}, protocol: {:?}",
                            e, src, dst, protocol
                        );
                    }
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
            config.name("kf0");
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

        let routes = {
            let rules = self.setting.rules.read().unwrap();
            rules
                .iter()
                .filter(|&v| v.rule_type == RuleType::Route)
                .flat_map(|v| v.values.clone())
                .collect::<Vec<_>>()
        };

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
        let relay = relay_tcp::Relay::new(self.setting.clone(), addr, self.tcp_nat.clone());
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
        let _src_port = packet.get_source();
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

        None
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
