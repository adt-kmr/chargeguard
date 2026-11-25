"""Packet parsing, flow aggregation and export to the node's flow schema."""
from netflow import synth
from netflow.exporter import to_node_record
from netflow.flowtable import FlowTable
from netflow.packets import TCP, UDP, build_frame, dns_query, parse_ethernet
from netflow.sources import read_pcap, write_pcap

C, S = "10.20.0.15", "10.20.0.1"


def test_tcp_session_counts_both_directions():
    (rec,) = synth.flows_of(synth.tcp_session(C, S, 50000, 9000, 1.0, [(300, 120)]))
    assert rec["IPV4_SRC_ADDR"] == C and rec["L4_DST_PORT"] == 9000 and rec["PROTOCOL"] == TCP
    # SYN, ACK, data, ACK, FIN, ACK from the client; SYN|ACK, data, FIN from the server
    assert (rec["IN_PKTS"], rec["OUT_PKTS"]) == (6, 3)
    assert rec["IN_BYTES"] == 6 * 40 + 300 and rec["OUT_BYTES"] == 3 * 40 + 120
    assert rec["CLIENT_TCP_FLAGS"] & 0x02 and rec["SERVER_TCP_FLAGS"] & 0x12 == 0x12


def test_refused_probe_and_exporter_marks_syn():
    (rec,) = synth.flows_of(synth.syn_probe(C, "192.168.1.254", 45000, 22, 1.0, "closed"))
    assert rec["CLIENT_TCP_FLAGS"] == 0x02 and rec["SERVER_TCP_FLAGS"] == 0x14
    node = to_node_record(rec, C)
    assert node["flags"] == "S" and node["dst"] == "192.168.1.254" and node["nf"] is rec


def test_dns_question_is_parsed():
    p = parse_ethernet(1.0, build_frame(C, S, UDP, 5353, 53, dns_query("abc.example.org", 16)))
    assert (p.dns_qtype, p.dns_qname) == (16, "abc.example.org")


def test_inbound_connection_is_oriented_from_the_charger():
    (rec,) = synth.flows_of(synth.tcp_session("192.168.1.9", C, 51000, 22, 1.0, [(100, 100)]))
    node = to_node_record(rec, C)
    assert node["src"] == C and node["dst"] == "192.168.1.9" and node["sport"] == 22


def test_timeouts_and_bounded_table():
    t = FlowTable(idle_timeout=1.0, active_timeout=5.0, max_flows=2)
    frames = [(float(i), build_frame(C, S, UDP, 40000 + i, 123, b"x" * 48)) for i in range(3)]
    out = []
    for ts, fr in frames:
        out += t.add(parse_ethernet(ts, fr))
    assert len(out) == 2 and len(t.flows) == 1          # idle flows exported as time moved on


def test_pcap_roundtrip(tmp_path):
    frames = synth.tcp_session(C, S, 50000, 9000, 1.0, [(2000, 500)]) + synth.dns_lookup(C, S, 5000, "csms.site.local", 1.5)
    path = tmp_path / "x.pcap"
    write_pcap(path, frames)
    pkts = list(read_pcap(path))
    assert len(pkts) == len(frames) and pkts[0].tcp_flags == 0x02
