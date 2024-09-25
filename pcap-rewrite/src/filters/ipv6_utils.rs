use log::trace;

use pnet_packet::ipv6::ExtensionPacket;
use pnet_packet::ipv6::FragmentPacket;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::Packet;
use pnet_packet::PacketSize;

use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ip::IpNextHeaderProtocols;

use libpcap_tools::Error;

// TODO: factorize with code at URL below
// From https://github.com/rusticata/pcap-analyzer/blob/3064dabbc51a19c51181dc223670ead34ce25844/libpcap-analyzer/src/analyzer.rs
pub fn is_ipv6_opt(opt: IpNextHeaderProtocol) -> bool {
    matches!(
        opt,
        IpNextHeaderProtocols::Hopopt
            | IpNextHeaderProtocols::Ipv6Opts
            | IpNextHeaderProtocols::Ipv6Route
            | IpNextHeaderProtocols::Ipv6Frag
            | IpNextHeaderProtocols::Esp
            | IpNextHeaderProtocols::Ah
            | IpNextHeaderProtocols::MobilityHeader
    )
}

pub fn get_fragment_packet_option_l4_protol4_payload<'a>(
    data: &'a [u8],
    ipv6: &'a Ipv6Packet,
) -> Result<(Option<FragmentPacket<'a>>, IpNextHeaderProtocol, &'a [u8]), Error> {
    // From https://github.com/rusticata/pcap-analyzer/blob/3064dabbc51a19c51181dc223670ead34ce25844/libpcap-analyzer/src/analyzer.rs
    let mut payload = ipv6.payload();
    let mut l4_proto = ipv6.get_next_header();

    if payload.is_empty() {
        // jumbogram ? (rfc2675)
        trace!("IPv6 length is 0. Jumbogram?");
        if data.len() >= 40 {
            payload = &data[40..];
        } else {
            return Err(Error::DataParser(
                "IPv6 length is 0, but frame is too short for an IPv6 header",
            ));
        }
    }

    let mut extensions = Vec::new();
    let mut fragment_packet_option = None;

    while is_ipv6_opt(l4_proto) {
        if l4_proto == IpNextHeaderProtocols::Esp {
            // ESP, don't try to get next layer protocol
            break;
        }

        let ext = ExtensionPacket::new(payload)
            .expect("Could not build IPv6 Extension packet from payload");
        let next_header = ext.get_next_header();
        trace!("option header: {}", l4_proto);
        if l4_proto == IpNextHeaderProtocols::Ipv6Frag {
            if fragment_packet_option.is_some() {
                return Err(Error::DataParser("multiple IPv6Frag extensions"));
            }
            fragment_packet_option = FragmentPacket::new(payload);
        }
        // XXX fixup wrong extension size calculation in pnet
        let offset = if l4_proto != IpNextHeaderProtocols::Ah {
            ext.packet_size()
        } else {
            // https://en.wikipedia.org/wiki/IPsec#Authentication_Header
            // The length of this Authentication Header in 4-octet units, minus 2. For example, an
            // AH value of 4 equals 3×(32-bit fixed-length AH fields) + 3×(32-bit ICV fields) − 2
            // and thus an AH value of 4 means 24 octets. Although the size is measured in 4-octet
            // units, the length of this header needs to be a multiple of 8 octets if carried in an
            // IPv6 packet. This restriction does not apply to an Authentication Header carried in
            // an IPv4 packet.
            let l1 = (payload[1] - 1) as usize;
            let val = l1 * 4 + l1 * 4 - 2;
            (val + 7) & (!7)
        };
        extensions.push((l4_proto, ext));
        l4_proto = next_header;
        payload = &payload[offset..];
    }

    Ok((fragment_packet_option, l4_proto, payload))
}
