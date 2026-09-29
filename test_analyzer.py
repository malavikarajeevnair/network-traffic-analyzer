import unittest
import main
from scapy.all import IP, TCP, UDP


class TestNetworkAnalyzer(unittest.TestCase):

    def setUp(self):
        main.packets.clear()
        main.protocol_counts.clear()
        main.source_stats.clear()
        main.destination_stats.clear()
        main.packet_sizes.clear()
        main.total_bytes = 0

    def test_tcp_packet_analysis(self):
        packet = IP(
            src="192.168.1.10",
            dst="192.168.1.20"
        ) / TCP(sport=1234, dport=80)

        main.analyze_packet(packet)

        self.assertEqual(len(main.packets), 1)
        self.assertEqual(main.protocol_counts["TCP"], 1)
        self.assertEqual(main.source_stats["192.168.1.10"]["packets"], 1)

    def test_udp_packet_analysis(self):
        packet = IP(
            src="192.168.1.30",
            dst="192.168.1.40"
        ) / UDP(sport=5000, dport=53)

        main.analyze_packet(packet)

        self.assertEqual(main.protocol_counts["UDP"], 1)
        self.assertEqual(main.packets[0]["Protocol"], "UDP")

    def test_packet_size_tracking(self):
        packet = IP(
            src="192.168.1.10",
            dst="192.168.1.20"
        ) / TCP()

        main.analyze_packet(packet)

        self.assertEqual(len(main.packet_sizes), 1)
        self.assertEqual(main.packet_sizes[0], len(packet))

    def test_total_bytes(self):
        packet = IP(
            src="192.168.1.10",
            dst="192.168.1.20"
        ) / TCP()

        main.analyze_packet(packet)

        self.assertEqual(main.total_bytes, len(packet))

    def test_anomaly_threshold(self):
        for _ in range(main.PACKET_THRESHOLD + 1):
            packet = IP(
                src="192.168.1.100",
                dst="192.168.1.1"
            ) / TCP()

            main.analyze_packet(packet)

        self.assertGreater(
            main.source_stats["192.168.1.100"]["packets"],
            main.PACKET_THRESHOLD
        )


if __name__ == "__main__":
    unittest.main()
