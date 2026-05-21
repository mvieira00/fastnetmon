#include <arpa/inet.h>
#include <iostream>
#include <netinet/in.h>
#include <string.h>
#include <string>
#include <vector>



/*
compiled this with:
g++ -std=c++20   -I fastnetmon/src     fastnetmon/src/scion_parser_test.cpp     fastnetmon/src/simple_packet_parser_ng.cpp     -llog4cpp     -o scion_test
and ran it with:
./scion_test
*/

#include "log4cpp/Category.hh"
log4cpp::Category& logger = log4cpp::Category::getRoot();

#include "simple_packet_parser_ng.hpp"
#include "network_data_structures.hpp"

using namespace network_data_stuctures;

int tests_passed = 0;
int tests_failed = 0;

void check(bool condition, std::string test_name) {
    if (condition) {
        std::cout << "PASS: " << test_name << std::endl;
        tests_passed++;
    } else {
        std::cout << "FAIL: " << test_name << std::endl;
        tests_failed++;
    }
}

template<typename T>
void check_eq(T actual, T expected, std::string test_name) {
    if (actual == expected) {
        std::cout << "PASS: " << test_name << std::endl;
        tests_passed++;
    } else {
        std::cout << "FAIL: " << test_name
                  << " (expected=" << +expected
                  << " actual=" << +actual << ")"
                  << std::endl;
        tests_failed++;
    }
}

void dump_bytes(const std::vector<uint8_t>& buf, size_t offset, size_t len, std::string label) {
    std::cout << "  [dump] " << label << " (offset=" << offset << ", len=" << len << "): ";
    for (size_t i = offset; i < offset + len && i < buf.size(); i++) {
        printf("%02x ", buf[i]);
    }
    std::cout << std::endl;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

int main() {

    // ── Test 1: real SCION packet ─────────────────────────────────────────
    {
        std::cout << "Test 1: real SCION packet" << std::endl;

        // Raw SCION packet starting directly at the SCION common header
        // No Ethernet/IP/UDP underlay
        std::vector<uint8_t> pkt = {
            0x00, 0x00, 0x00, 0x01, 0x11, 0x22, 0x00, 0x16,
            0x01, 0x00, 0x00, 0x00,
            // DstIA
            0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09,
            // SrcIA
            0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // DstHostAddr: 129.132.175.104
            0x81, 0x84, 0xaf, 0x68,
            // SrcHostAddr: 188.60.224.160
            0xbc, 0x3c, 0xe0, 0xa0,
            // PathMeta
            0x00, 0x00, 0x20, 0x82,
            // InfoField 0
            0x00, 0x00, 0x35, 0xd0, 0x6a, 0x0a, 0xf4, 0xc6,
            // InfoField 1
            0x00, 0x00, 0x54, 0xd6, 0x6a, 0x0a, 0xf4, 0x1a,
            // InfoField 2
            0x01, 0x00, 0xea, 0x69, 0x6a, 0x0a, 0xf4, 0xd0,
            // HopField 0
            0x00, 0x3f, 0x00, 0x01, 0x00, 0x00, 0x41, 0x69, 
            0xd3, 0x4b, 0x48, 0xf5,
            // HopField 1
            0x00, 0x3f, 0x00, 0x00, 0x00, 0x03, 0x64, 0xe9, 
            0x2c, 0x3c, 0x51, 0x5a,
            // HopField 2
            0x00, 0x3f, 0x00, 0x1f, 0x00, 0x00, 0xab, 0x74, 
            0x15, 0xa9, 0x1b, 0x8c,
            // HopField 3
            0x00, 0x3f, 0x00, 0x00, 0x00, 0x1f, 0x67, 0x2b, 
            0x43, 0x53, 0x77, 0x4a,
            // HopField 4
            0x00, 0x3f, 0x00, 0x00, 0x00, 0x05, 0x1c, 0x1f, 
            0xc5, 0x48, 0x95, 0xa2,
            // HopField 5
            0x00, 0x3f, 0x00, 0x01, 0x00, 0x00, 0x65, 0xbb, 
            0x3c, 0xfe, 0x9c, 0x06,
            //SCION UDP header
            0xbc, 0x4c, 0x75, 0x59, 0x00, 0x16, 0xf7, 0xca,
            // payload: "helloworldtest"
            0x68, 0x65, 0x6c, 0x6c, 0x6f,
            0x77, 0x6f, 0x72, 0x6c, 0x64,
            0x74, 0x65, 0x73, 0x74
        };

        // Dump the key sections
        std::cout << "  [debug] packet size: " << pkt.size() << std::endl;
        dump_bytes(pkt, 0,  12, "SCION Common Header");
        dump_bytes(pkt, 12, 16, "SCION Adress Header");
        dump_bytes(pkt, 28,  4, "DstHostAddr");
        dump_bytes(pkt, 32,  4, "SrcHostAddr");
        dump_bytes(pkt, 36,  4, "PathMeta");
        dump_bytes(pkt, 40,  8, "InfoField 0");
        dump_bytes(pkt, 48,  8, "InfoField 1");
        dump_bytes(pkt, 56,  8, "InfoField 2");
        dump_bytes(pkt, 64,  12, "Hopfield 0");
        dump_bytes(pkt, 76,  12, "Hopfield 1");
        dump_bytes(pkt, 88,  12, "Hopfield 2");
        dump_bytes(pkt, 100,  12, "Hopfield 3");
        dump_bytes(pkt, 112,  12, "Hopfield 4");
        dump_bytes(pkt, 124,  12, "Hopfield 5");

        simple_packet_t packet;
        parser_options_t options;

        // Call parse_scion_packet directly since there is no Ethernet/IP/UDP wrapper
        parser_code_t result = parse_scion_packet(
            pkt.data(),
            pkt.data() + pkt.size(),
            packet,
            options
        );

        check(result == parser_code_t::success,  "returns success");
        check(packet.is_scion == true,           "is_scion set");
        
        check_eq(packet.scion_version, (uint8_t) 0000, "Version: 0x00");
        check_eq(packet.scion_flow_id, (uint32_t) 00000000000000000001, "FlowID: 0x00001");
        check_eq(packet.scion_next_hdr, (uint8_t) 17, "Is next header 17");
        check_eq(packet.scion_hdr_len,  (uint8_t) (34*4), "HdrLen: 32");
        check_eq(packet.scion_path_type, (uint8_t) 1, "SCION (1)");
        
        // Adress Header
        // DstHostAddr: 129.132.175.104
        check_eq(packet.scion_dst_host_adr_ipv4, htonl(0x8184af68), "DstHostAddr is 129.132.175.104");

        // SrcHostAddr: 188.60.224.160
        check_eq(packet.scion_src_host_adr_ipv4, htonl(0xbc3ce0a0), "SrcHostAddr is 188.60.224.160");
    
        check_eq(packet.scion_dst_isd, (uint16_t)64,  "dst ISD is 64");
        check_eq(packet.scion_src_isd, (uint16_t)64,  "src ISD is 64");
        check_eq(packet.scion_dst_as, (uint64_t) 0x000200000009,  "dst AS is 2:0:9");
        check_eq(packet.scion_src_as, (uint64_t) 0x000200000000,  "src AS is 2:0:0");

        // Path Meta Header
        check_eq(packet.scion_num_info_fields, (uint8_t)3,  "3 info fields");
        check_eq(packet.scion_num_hop_fields,  (uint8_t)6,  "6 hop fields");

        // we'll check the scion info fields
        // InfoField 0
        check_eq(packet.scion_info_fields[0].ConstructionDir, (bool) 0, "ConsDir not set");
        check_eq(packet.scion_info_fields[0].peering, (bool) 0, "Peer not set");
        check_eq(packet.scion_info_fields[0].SegID, (uint16_t) 0x35D0, "0x35D0");
        check_eq(packet.scion_info_fields[0].timestamp, (uint32_t) 1779102918, "May 18, 2026 11:15.....");

        // InfoField 1
        check_eq(packet.scion_info_fields[1].ConstructionDir, (bool) 0, "ConsDir not set");
        check_eq(packet.scion_info_fields[1].peering, (bool) 0, "Peer not set");
        check_eq(packet.scion_info_fields[1].SegID, (uint16_t) 0x54d6, "0x54d6");
        check_eq(packet.scion_info_fields[1].timestamp, (uint32_t) 1779102746, "May 18, 2026 11:12....");
        // InfoField 2
        check_eq(packet.scion_info_fields[2].ConstructionDir, (bool) 1, "ConsDir is set");
        check_eq(packet.scion_info_fields[2].peering, (bool) 0, "Peer not set");
        check_eq(packet.scion_info_fields[2].SegID, (uint16_t) 0xea69, "0xea69 to 63094");
        check_eq(packet.scion_info_fields[2].timestamp, (uint32_t) 1779102928, "May 18, 2026 11:15.....");

        // check at least the first Hopfield
        // HopField 0
        check_eq(packet.scion_hop_fields[0].CI, (uint16_t) 1, "ConsIngress IFID: 1");
        check_eq(packet.scion_hop_fields[0].CE, (uint16_t) 0, "ConsEgress IFID: 0");
        check_eq(packet.scion_hop_fields[0].Exptime, (uint8_t) 63, "Exptime: 63");
        std::cout << "  [debug] packet.scion_hop_fields[0].Exptime: " << +packet.scion_hop_fields[0].Exptime << std::endl;

        std::cout << std::endl;
    }

    
    // ── Test 2: real SCION packet IPv6 Dst Addr andIPv4 Src Addr ────────────────
    {
        std::cout << "Test 2: real SCION packet IPv6 Dst Addr andIPv4 Src Addr" << std::endl;

        std::vector<uint8_t> pkt = {
            // SCION Common  Header
            0, 0, 0, 1, 17, 26, 0, 113, 1, 48, 0, 0,
            // Dst ISD and AS
            0, 2, 255, 0, 0, 0, 2, 17,
            // Src ISD and AS
            0, 1, 255, 0, 0, 0, 1, 18,
            // DstHostAdr
            253, 0, 240, 13, 202, 254, 0, 0, 0, 0, 0, 0, 127, 0, 0, 60,
            // SrcHostAdr
            127, 0, 0, 61,
            //Path Meta Header
            0, 0, 32, 64,
            // Info Field 0
            2, 0, 121, 134, 106, 11, 106, 203,
            // Info Field 1
            3, 0, 42, 105, 106, 11, 106, 203,
            // HopField 0
            0, 63, 1, 238, 0, 0, 63, 250, 89, 155, 95, 125,
            // HopField 1
            0, 63, 0, 101, 0, 103, 198, 187, 16, 107, 195, 191,
            // HopField 2
            0, 63, 0, 5, 0, 0, 214, 14, 39, 206, 119, 240,
            // Other headers and payload(?)
            127, 254, 127, 255, 0, 113, 241, 136,
            123, 34, 115, 101, 114, 118, 101, 114, 34, 58, 34, 50, 45,
            102, 102, 48, 48, 58, 48, 58, 50, 49, 49, 34, 44, 34, 109,
            101, 115, 115, 97, 103, 101, 34, 58, 34, 112, 105, 110, 103,
            34, 44, 34, 116, 114, 97, 99, 101, 34, 58, 34, 65, 65, 65,
            65, 65, 65, 65, 65, 65, 65, 66, 113, 78, 104, 121, 81, 81,
            79, 117, 88, 66, 106, 122, 51, 51, 97, 86, 79, 87, 49, 121,
            82, 97, 106, 89, 99, 107, 69, 68, 114, 108, 119, 89, 66, 65,
            65, 65, 65, 65, 65, 61, 61, 34, 125
        };

        simple_packet_t packet;
        parser_options_t options;

        // Call parse_scion_packet directly since there is no Ethernet/IP/UDP wrapper
        parser_code_t result = parse_scion_packet(
            pkt.data(),
            pkt.data() + pkt.size(),
            packet,
            options
        );


        check(result == parser_code_t::success, "returns success");
        check(packet.is_scion == true,          "is_scion set");

        // Common Header
        check_eq(packet.scion_version,   (uint8_t)0,  "Version: 0");
        check_eq(packet.scion_flow_id,   (uint32_t)1, "FlowID: 1");
        check_eq(packet.scion_next_hdr,  (uint8_t)17, "NextHdr: 17 (UDP)");
        check_eq(packet.scion_hdr_len,  (uint8_t)(26*4), "HdrLen: 26");
        check_eq(packet.scion_path_type, (uint8_t)1,  "PathType: 1 (SCION)");

        // Address Header
        // DstHostAddr IPv6: fd00:f00d:cafe:0:0:0:7f00:3c
        // Expected IPv6 address: fd00:f00d:cafe::7f00:003c
        uint8_t expected_ipv6[16] = {
            0xfd, 0x00, 0xf0, 0x0d,
            0xca, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x3c
        };

        check(memcmp(packet.scion_dst_host_adr_ipv6.s6_addr, expected_ipv6, 16) == 0, "DstHostAddr is fd00:f00d:cafe::7f00:003c");
        // Option 2: use inet_ntop to convert to readable string
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &packet.scion_dst_host_adr_ipv6, buf, sizeof(buf));
        std::cout << "packet.scion_dst_host_adr_ipv6: " << buf << std::endl;
        // Src is IPv4: 127.0.0.61
        check_eq(packet.scion_src_host_adr_ipv4, htonl(0x7f00003d), "SrcHostAddr is 127.0.0.61");

        // ISD-AS
        check_eq(packet.scion_dst_isd, (uint16_t)2,              "dst ISD is 2");
        check_eq(packet.scion_src_isd, (uint16_t)1,              "src ISD is 1");
        check_eq(packet.scion_dst_as,  (uint64_t)0xff0000000211, "dst AS is ff00:0:211");
        check_eq(packet.scion_src_as,  (uint64_t)0xff0000000112, "src AS is ff00:0:112");

        // PathMeta: Seg0Len=2, Seg1Len=1, Seg2Len=0 → 2 info fields, 3 hop fields
        check_eq(packet.scion_num_info_fields, (uint8_t)2, "2 info fields");
        check_eq(packet.scion_num_hop_fields,  (uint8_t)3, "3 hop fields");

        // InfoField 0: flags=0x02 → C=0, P=1
        // bytes: 02 00 79 86 6a 0b 6a cb
        check_eq(packet.scion_info_fields[0].ConstructionDir, (bool)false,  "info[0] ConsDir not set");
        check_eq(packet.scion_info_fields[0].peering,         (bool)true, "info[0] Peer set");
        check_eq(packet.scion_info_fields[0].SegID,           (uint16_t)0x7986,     "info[0] SegID=0x7986");
        check_eq(packet.scion_info_fields[0].timestamp,       (uint32_t)0x6a0b6acb, "info[0] timestamp");

        // InfoField 1: flags=0x03 → C=1, P=1
        // bytes: 03 00 2a 69 6a 0b 6a cb
        check_eq(packet.scion_info_fields[1].ConstructionDir, (bool)true, "info[1] ConsDir set");
        check_eq(packet.scion_info_fields[1].peering,         (bool)true, "info[1] Peer set");
        check_eq(packet.scion_info_fields[1].SegID,           (uint16_t)0x2a69,     "info[1] SegID=0x2a69");
        check_eq(packet.scion_info_fields[1].timestamp,       (uint32_t)0x6a0b6acb, "info[1] timestamp");

        // HopField 0: bytes: 00 3f 01 ee 00 00 3f fa 59 9b 5f 7d
        check_eq(packet.scion_hop_fields[0].CI,      (uint16_t)494, "hop[0] ConsIngress=494");
        check_eq(packet.scion_hop_fields[0].CE,      (uint16_t)0,   "hop[0] ConsEgress=0");
        check_eq(packet.scion_hop_fields[0].Exptime, (uint8_t)63,   "hop[0] Exptime=63");
        
        // HopField 1: 00 3f 00 65 00 67 c6 bb 10 6b c3 bf
        check_eq(packet.scion_hop_fields[1].CI,      (uint16_t)101, "hop[1] ConsIngress=101");
        check_eq(packet.scion_hop_fields[1].CE,      (uint16_t)103, "hop[1] ConsEgress=103");
        check_eq(packet.scion_hop_fields[1].Exptime, (uint8_t)63,   "hop[1] Exptime=63");

        // HopField 2: 00 3f 00 05 00 00 d6 0e 27 ce 77 f0
        check_eq(packet.scion_hop_fields[2].CI,      (uint16_t)5,  "hop[2] ConsIngress=5");
        check_eq(packet.scion_hop_fields[2].CE,      (uint16_t)0,  "hop[2] ConsEgress=0");
        check_eq(packet.scion_hop_fields[2].Exptime, (uint8_t)63,  "hop[2] Exptime=63");

        std::cout << std::endl;
    }

    // ── Test 3: real SCION packet ────────────────
    {
        std::cout << "Test 3: real SCION packet" << std::endl;

        std::vector<uint8_t> pkt = {

            // SCION Common  Header
            0, 0, 0, 1, 17, 32, 0, 113, 1, 51, 0, 0,
            // SCION Address Header
            // Dst ISD and AS
            0, 2, 255, 0, 0, 0, 2, 17,
            // Src ISD and AS
            0, 2, 255, 0, 0, 0, 2, 32,
            // DstHostAdr
            253, 0, 240, 13, 202, 254, 0, 0, 0, 0, 0, 0, 127, 0, 0, 60,
            // SrcHostAdr
            253, 0, 240, 13, 202, 254, 0, 0, 0, 0, 0, 0, 127, 0, 0, 71, 
            //Path Meta Header (SegLen0 = 2, SegLen1 = 2, SegLen2 = 0)
            0, 0, 32, 128,
            // Info Field 0
            0, 0, 201, 160, 106, 11, 106, 229, 
            // Info Field 1
            1, 0, 200, 248, 106, 11, 106, 123, 
            // HopField 0
            0, 63, 1, 247, 0, 0, 16, 83, 102, 87, 63, 201, 
            // HopField 1
            0, 63, 0, 0, 1, 194, 228, 130, 133, 127, 84, 60, 
            // HopField 2
            0, 63, 0, 0, 1, 196, 99, 250, 183, 153, 120, 247, 
            // HopField 3
            0, 63, 0, 8, 0, 0, 223, 238, 59, 106, 117, 12, 
            // Other headers and payload(?)
            127, 254, 127, 255, 0, 113, 30, 106, 123,
            34, 115, 101, 114, 118, 101, 114, 34, 58, 34, 50, 45, 102, 102, 48, 48, 58,
            48, 58, 50, 49, 49, 34, 44, 34, 109, 101, 115, 115, 97, 103, 101, 34, 58,
            34, 112, 105, 110, 103, 34, 44, 34, 116, 114, 97, 99, 101, 34, 58, 34, 65,
            65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 71, 114, 79, 109, 53, 57, 75, 108,
            67, 111, 122, 99, 107, 119, 115, 77, 73, 73, 73, 68, 75, 66, 113, 122, 112,
            117, 102, 83, 112, 81, 113, 77, 66, 65, 65, 65, 65, 65, 65, 61, 61, 34, 125
        };

        simple_packet_t packet;
        parser_options_t options;

        // Call parse_scion_packet directly since there is no Ethernet/IP/UDP wrapper
        parser_code_t result = parse_scion_packet(
            pkt.data(),
            pkt.data() + pkt.size(),
            packet,
            options
        );


        check(result == parser_code_t::success, "returns success");
        check(packet.is_scion == true,          "is_scion set");

        // Common Header
        check_eq(packet.scion_version,   (uint8_t)0,  "Version: 0");
        check_eq(packet.scion_flow_id,   (uint32_t)1, "FlowID: 1");
        check_eq(packet.scion_next_hdr,  (uint8_t)17, "NextHdr: 17 (UDP)");
        check_eq(packet.scion_hdr_len,  (uint8_t)(32*4), "HdrLen: 32");
        check_eq(packet.scion_path_type, (uint8_t)1,  "PathType: 1 (SCION)");

        // Address Header
        // Both DstHostAddr and SrcHostAddr are IPv6 (DL=3, SL=3)

        // DstHostAddr: fd00:f00d:cafe::7f00:003c
        uint8_t expected_dst_ipv6[16] = {
            0xfd, 0x00, 0xf0, 0x0d,
            0xca, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x3c
        };
        check(memcmp(packet.scion_dst_host_adr_ipv6.s6_addr, expected_dst_ipv6, 16) == 0, "DstHostAddr is fd00:f00d:cafe::7f00:003c");

        // SrcHostAddr: fd00:f00d:cafe::7f00:0047
        uint8_t expected_src_ipv6[16] = {
            0xfd, 0x00, 0xf0, 0x0d,
            0xca, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x47
        };
        check(memcmp(packet.scion_src_host_adr_ipv6.s6_addr, expected_src_ipv6, 16) == 0, "SrcHostAddr is fd00:f00d:cafe::7f00:0047");

        // ISD-AS
        check_eq(packet.scion_dst_isd, (uint16_t)2,              "dst ISD is 2");
        check_eq(packet.scion_src_isd, (uint16_t)2,              "src ISD is 2");
        check_eq(packet.scion_dst_as,  (uint64_t)0xff0000000211, "dst AS is ff00:0:211");
        check_eq(packet.scion_src_as,  (uint64_t)0xff0000000220, "src AS is ff00:0:220");

        // PathMeta: Seg0Len=2, Seg1Len=2, Seg2Len=0 → 2 info fields, 4 hop fields
        check_eq(packet.scion_num_info_fields, (uint8_t)2, "2 info fields");
        check_eq(packet.scion_num_hop_fields,  (uint8_t)4, "4 hop fields");

        // InfoField 0: flags=0x00 → C=0, P=0
        // bytes: 00 00 c9 a0 6a 0b 6a e5
        check_eq(packet.scion_info_fields[0].ConstructionDir, (bool)false, "info[0] ConsDir not set");
        check_eq(packet.scion_info_fields[0].peering,         (bool)false, "info[0] Peer not set");
        check_eq(packet.scion_info_fields[0].SegID,           (uint16_t)0xc9a0,     "info[0] SegID=0xc9a0");
        check_eq(packet.scion_info_fields[0].timestamp,       (uint32_t)0x6a0b6ae5, "info[0] timestamp");

        // InfoField 1: flags=0x01 → C=1, P=0
        // bytes: 01 00 c8 f8 6a 0b 6a 7b
        check_eq(packet.scion_info_fields[1].ConstructionDir, (bool)true,  "info[1] ConsDir set");
        check_eq(packet.scion_info_fields[1].peering,         (bool)false, "info[1] Peer not set");
        check_eq(packet.scion_info_fields[1].SegID,           (uint16_t)0xc8f8,     "info[1] SegID=0xc8f8");
        check_eq(packet.scion_info_fields[1].timestamp,       (uint32_t)0x6a0b6a7b, "info[1] timestamp");

        // HopField 0: 00 3f 01 f7 00 00 10 53 66 57 3f c9
        check_eq(packet.scion_hop_fields[0].CI,      (uint16_t)503, "hop[0] ConsIngress=503");
        check_eq(packet.scion_hop_fields[0].CE,      (uint16_t)0,   "hop[0] ConsEgress=0");
        check_eq(packet.scion_hop_fields[0].Exptime, (uint8_t)63,   "hop[0] Exptime=63");

        // HopField 1: 00 3f 00 00 01 c2 e4 82 85 7f 54 3c
        check_eq(packet.scion_hop_fields[1].CI,      (uint16_t)0,   "hop[1] ConsIngress=0");
        check_eq(packet.scion_hop_fields[1].CE,      (uint16_t)450, "hop[1] ConsEgress=450");
        check_eq(packet.scion_hop_fields[1].Exptime, (uint8_t)63,   "hop[1] Exptime=63");

        // HopField 2: 00 3f 00 00 01 c4 63 fa b7 99 78 f7
        check_eq(packet.scion_hop_fields[2].CI,      (uint16_t)0,   "hop[2] ConsIngress=0");
        check_eq(packet.scion_hop_fields[2].CE,      (uint16_t)452, "hop[2] ConsEgress=452");
        check_eq(packet.scion_hop_fields[2].Exptime, (uint8_t)63,   "hop[2] Exptime=63");

        // HopField 3: 00 3f 00 08 00 00 df ee 3b 6a 75 0c
        check_eq(packet.scion_hop_fields[3].CI,      (uint16_t)8,  "hop[3] ConsIngress=8");
        check_eq(packet.scion_hop_fields[3].CE,      (uint16_t)0,  "hop[3] ConsEgress=0");
        check_eq(packet.scion_hop_fields[3].Exptime, (uint8_t)63,  "hop[3] Exptime=63");

        std::cout << std::endl;
    }


    // ── Test 3: real SCION packet, both Dst/SrcHostAddr are IPv6 ────────────────
    {
        std::cout << "Test 3: real SCION packet, both Dst/SrcHostAddr are IPv6" << std::endl;

        std::vector<uint8_t> pkt = {

            // SCION Common  Header
            0, 0, 0, 1, 17, 32, 0, 113, 1, 51, 0, 0,
            // SCION Address Header
            // Dst ISD and AS
            0, 2, 255, 0, 0, 0, 2, 17,
            // Src ISD and AS
            0, 2, 255, 0, 0, 0, 2, 32,
            // DstHostAdr
            253, 0, 240, 13, 202, 254, 0, 0, 0, 0, 0, 0, 127, 0, 0, 60,
            // SrcHostAdr
            253, 0, 240, 13, 202, 254, 0, 0, 0, 0, 0, 0, 127, 0, 0, 71, 
            //Path Meta Header (SegLen0 = 2, SegLen1 = 2, SegLen2 = 0)
            0, 0, 32, 128,
            // Info Field 0
            0, 0, 201, 160, 106, 11, 106, 229, 
            // Info Field 1
            1, 0, 200, 248, 106, 11, 106, 123, 
            // HopField 0
            0, 63, 1, 247, 0, 0, 16, 83, 102, 87, 63, 201, 
            // HopField 1
            0, 63, 0, 0, 1, 194, 228, 130, 133, 127, 84, 60, 
            // HopField 2
            0, 63, 0, 0, 1, 196, 99, 250, 183, 153, 120, 247, 
            // HopField 3
            0, 63, 0, 8, 0, 0, 223, 238, 59, 106, 117, 12, 
            // Other headers and payload(?)
            127, 254, 127, 255, 0, 113, 30, 106, 123,
            34, 115, 101, 114, 118, 101, 114, 34, 58, 34, 50, 45, 102, 102, 48, 48, 58,
            48, 58, 50, 49, 49, 34, 44, 34, 109, 101, 115, 115, 97, 103, 101, 34, 58,
            34, 112, 105, 110, 103, 34, 44, 34, 116, 114, 97, 99, 101, 34, 58, 34, 65,
            65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 71, 114, 79, 109, 53, 57, 75, 108,
            67, 111, 122, 99, 107, 119, 115, 77, 73, 73, 73, 68, 75, 66, 113, 122, 112,
            117, 102, 83, 112, 81, 113, 77, 66, 65, 65, 65, 65, 65, 65, 61, 61, 34, 125
        };

        simple_packet_t packet;
        parser_options_t options;

        // Call parse_scion_packet directly since there is no Ethernet/IP/UDP wrapper
        parser_code_t result = parse_scion_packet(
            pkt.data(),
            pkt.data() + pkt.size(),
            packet,
            options
        );


        check(result == parser_code_t::success, "returns success");
        check(packet.is_scion == true,          "is_scion set");

        // Common Header
        check_eq(packet.scion_version,   (uint8_t)0,  "Version: 0");
        check_eq(packet.scion_flow_id,   (uint32_t)1, "FlowID: 1");
        check_eq(packet.scion_next_hdr,  (uint8_t)17, "NextHdr: 17 (UDP)");
        check_eq(packet.scion_hdr_len,  (uint8_t)(32*4), "HdrLen: 32");
        check_eq(packet.scion_path_type, (uint8_t)1,  "PathType: 1 (SCION)");

        // Address Header
        // Both DstHostAddr and SrcHostAddr are IPv6 (DL=3, SL=3)

        // DstHostAddr: fd00:f00d:cafe::7f00:003c
        uint8_t expected_dst_ipv6[16] = {
            0xfd, 0x00, 0xf0, 0x0d,
            0xca, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x3c
        };
        check(memcmp(packet.scion_dst_host_adr_ipv6.s6_addr, expected_dst_ipv6, 16) == 0, "DstHostAddr is fd00:f00d:cafe::7f00:003c");

        // SrcHostAddr: fd00:f00d:cafe::7f00:0047
        uint8_t expected_src_ipv6[16] = {
            0xfd, 0x00, 0xf0, 0x0d,
            0xca, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x47
        };
        check(memcmp(packet.scion_src_host_adr_ipv6.s6_addr, expected_src_ipv6, 16) == 0, "SrcHostAddr is fd00:f00d:cafe::7f00:0047");

        // ISD-AS
        check_eq(packet.scion_dst_isd, (uint16_t)2,              "dst ISD is 2");
        check_eq(packet.scion_src_isd, (uint16_t)2,              "src ISD is 2");
        check_eq(packet.scion_dst_as,  (uint64_t)0xff0000000211, "dst AS is ff00:0:211");
        check_eq(packet.scion_src_as,  (uint64_t)0xff0000000220, "src AS is ff00:0:220");

        // PathMeta: Seg0Len=2, Seg1Len=2, Seg2Len=0 → 2 info fields, 4 hop fields
        check_eq(packet.scion_num_info_fields, (uint8_t)2, "2 info fields");
        check_eq(packet.scion_num_hop_fields,  (uint8_t)4, "4 hop fields");

        // InfoField 0: flags=0x00 → C=0, P=0
        // bytes: 00 00 c9 a0 6a 0b 6a e5
        check_eq(packet.scion_info_fields[0].ConstructionDir, (bool)false, "info[0] ConsDir not set");
        check_eq(packet.scion_info_fields[0].peering,         (bool)false, "info[0] Peer not set");
        check_eq(packet.scion_info_fields[0].SegID,           (uint16_t)0xc9a0,     "info[0] SegID=0xc9a0");
        check_eq(packet.scion_info_fields[0].timestamp,       (uint32_t)0x6a0b6ae5, "info[0] timestamp");

        // InfoField 1: flags=0x01 → C=1, P=0
        // bytes: 01 00 c8 f8 6a 0b 6a 7b
        check_eq(packet.scion_info_fields[1].ConstructionDir, (bool)true,  "info[1] ConsDir set");
        check_eq(packet.scion_info_fields[1].peering,         (bool)false, "info[1] Peer not set");
        check_eq(packet.scion_info_fields[1].SegID,           (uint16_t)0xc8f8,     "info[1] SegID=0xc8f8");
        check_eq(packet.scion_info_fields[1].timestamp,       (uint32_t)0x6a0b6a7b, "info[1] timestamp");

        // HopField 0: 00 3f 01 f7 00 00 10 53 66 57 3f c9
        check_eq(packet.scion_hop_fields[0].CI,      (uint16_t)503, "hop[0] ConsIngress=503");
        check_eq(packet.scion_hop_fields[0].CE,      (uint16_t)0,   "hop[0] ConsEgress=0");
        check_eq(packet.scion_hop_fields[0].Exptime, (uint8_t)63,   "hop[0] Exptime=63");

        // HopField 1: 00 3f 00 00 01 c2 e4 82 85 7f 54 3c
        check_eq(packet.scion_hop_fields[1].CI,      (uint16_t)0,   "hop[1] ConsIngress=0");
        check_eq(packet.scion_hop_fields[1].CE,      (uint16_t)450, "hop[1] ConsEgress=450");
        check_eq(packet.scion_hop_fields[1].Exptime, (uint8_t)63,   "hop[1] Exptime=63");

        // HopField 2: 00 3f 00 00 01 c4 63 fa b7 99 78 f7
        check_eq(packet.scion_hop_fields[2].CI,      (uint16_t)0,   "hop[2] ConsIngress=0");
        check_eq(packet.scion_hop_fields[2].CE,      (uint16_t)452, "hop[2] ConsEgress=452");
        check_eq(packet.scion_hop_fields[2].Exptime, (uint8_t)63,   "hop[2] Exptime=63");

        // HopField 3: 00 3f 00 08 00 00 df ee 3b 6a 75 0c
        check_eq(packet.scion_hop_fields[3].CI,      (uint16_t)8,  "hop[3] ConsIngress=8");
        check_eq(packet.scion_hop_fields[3].CE,      (uint16_t)0,  "hop[3] ConsEgress=0");
        check_eq(packet.scion_hop_fields[3].Exptime, (uint8_t)63,  "hop[3] Exptime=63");

        std::cout << std::endl;
    }

    // ── Test 4: real SCION packet ────────────────
    {
        std::cout << "Test 4: real SCION packet" << std::endl;

        std::vector<uint8_t> pkt = {
            // SCION Common  Header
            0, 0, 0, 1, 17, 24, 0, 113, 1, 3, 0, 0,
            // SCION Address Header
            // Dst ISD and AS
            0, 2, 255, 0, 0, 0, 2, 16,
            // Src ISD and AS
            0, 2, 255, 0, 0, 0, 2, 34, 
            // DstHostAdr
            127, 0, 0, 119, 
            // SrcHostAdr
            253, 0, 240, 13, 202, 254, 0, 0, 0, 0, 0, 0, 127, 0, 0, 85, 
            //Path Meta Header (SegLen0 = 3, SegLen1 = 0, SegLen2 = 0)
            0, 0, 48, 0,
            // Info Field 0
            0, 0, 243, 145, 106, 11, 107, 16, 
            // HopField 0
            0, 63, 1, 45, 0, 0, 126, 219, 66, 222, 126, 2, 
            // HopField 1
            0, 63, 0, 8, 0, 4, 171, 146, 47, 51, 222, 25,
            // HopField 2 
            0, 63, 0, 0, 1, 196, 16, 193, 164, 132, 129, 60,
            // Other headers and payload(?)
            127, 254, 127, 255, 0, 113, 77, 29, 123, 34, 115, 101, 114, 118, 101,
            114, 34, 58, 34, 50, 45, 102, 102, 48, 48, 58, 48, 58, 50, 49, 48, 34, 
            44, 34, 109, 101, 115, 115, 97, 103, 101, 34, 58, 34, 112, 105, 110, 103, 
            34, 44, 34, 116, 114, 97, 99, 101, 34, 58, 34, 65, 65, 65, 65, 65, 65, 65, 
            65, 65, 65, 65, 88, 114, 105, 81, 51, 98, 115, 65, 66, 50, 83, 75, 52, 110, 
            112, 98, 110, 47, 113, 77, 74, 70, 54, 52, 107, 78, 50, 55, 65, 65, 100, 107, 
            66, 65, 65, 65, 65, 65, 65, 61, 61, 34, 125 
        }; 

        std::cout << pkt.size() << std::endl;
        std::cout << 24*4 + 113 << std::endl;


        simple_packet_t packet;
        parser_options_t options;

        

        // Call parse_scion_packet directly since there is no Ethernet/IP/UDP wrapper
        parser_code_t result = parse_scion_packet(
            pkt.data(),
            pkt.data() + pkt.size(),
            packet,
            options
        );


        check(result == parser_code_t::success, "returns success");
        check(packet.is_scion == true,          "is_scion set");

        // Common Header
        check_eq(packet.scion_version,   (uint8_t)0,     "Version: 0");
        check_eq(packet.scion_flow_id,   (uint32_t)1,    "FlowID: 1");
        check_eq(packet.scion_next_hdr,  (uint8_t)17,    "NextHdr: 17 (UDP)");
        check_eq(packet.scion_hdr_len,   (uint8_t)(24*4),"HdrLen: 96 bytes");
        check_eq(packet.scion_path_type, (uint8_t)1,     "PathType: 1 (SCION)");

        // Address Header
        // DL=0 (4 bytes IPv4 dst), SL=3 (16 bytes IPv6 src)
        check_eq(packet.ip_protocol_version, (uint8_t)4, "ip_protocol_version is 4");

        // DstHostAddr IPv4: 127.0.0.119
        check_eq(packet.scion_dst_host_adr_ipv4, htonl(0x7f000077),
                "DstHostAddr is 127.0.0.119");

        // SrcHostAddr IPv6: fd00:f00d:cafe::7f00:0055
        uint8_t expected_src_ipv6[16] = {
            0xfd, 0x00, 0xf0, 0x0d,
            0xca, 0xfe, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x7f, 0x00, 0x00, 0x55
        };
        check(memcmp(packet.scion_src_host_adr_ipv6.s6_addr,
                    expected_src_ipv6, 16) == 0,
            "SrcHostAddr is fd00:f00d:cafe::7f00:0055");

        // ISD-AS
        check_eq(packet.scion_dst_isd, (uint16_t)2,              "dst ISD is 2");
        check_eq(packet.scion_src_isd, (uint16_t)2,              "src ISD is 2");
        check_eq(packet.scion_dst_as,  (uint64_t)0xff0000000210, "dst AS is ff00:0:210");
        check_eq(packet.scion_src_as,  (uint64_t)0xff0000000222, "src AS is ff00:0:222");

        // PathMeta: Seg0Len=3, Seg1Len=0, Seg2Len=0 → 1 info field, 3 hop fields
        check_eq(packet.scion_num_info_fields, (uint8_t)1, "1 info field");
        check_eq(packet.scion_num_hop_fields,  (uint8_t)3, "3 hop fields");

        // InfoField 0: flags=0x00 → C=0, P=0
        // bytes: 00 00 f3 91 6a 0b 6b 10
        check_eq(packet.scion_info_fields[0].ConstructionDir, (bool)false, "info[0] ConsDir not set");
        check_eq(packet.scion_info_fields[0].peering,         (bool)false, "info[0] Peer not set");
        check_eq(packet.scion_info_fields[0].SegID,           (uint16_t)0xf391,     "info[0] SegID=0xf391");
        check_eq(packet.scion_info_fields[0].timestamp,       (uint32_t)0x6a0b6b10, "info[0] timestamp");

        // HopField 0: 00 3f 01 2d 00 00 7e db 42 de 7e 02
        check_eq(packet.scion_hop_fields[0].CI,      (uint16_t)301, "hop[0] ConsIngress=301");
        check_eq(packet.scion_hop_fields[0].CE,      (uint16_t)0,   "hop[0] ConsEgress=0");
        check_eq(packet.scion_hop_fields[0].Exptime, (uint8_t)63,   "hop[0] Exptime=63");

        // HopField 1: 00 3f 00 08 00 04 ab 92 2f 33 de 19
        check_eq(packet.scion_hop_fields[1].CI,      (uint16_t)8,  "hop[1] ConsIngress=8");
        check_eq(packet.scion_hop_fields[1].CE,      (uint16_t)4,  "hop[1] ConsEgress=4");
        check_eq(packet.scion_hop_fields[1].Exptime, (uint8_t)63,  "hop[1] Exptime=63");

        // HopField 2: 00 3f 00 00 01 c4 10 c1 a4 84 81 3c
        check_eq(packet.scion_hop_fields[2].CI,      (uint16_t)0,   "hop[2] ConsIngress=0");
        check_eq(packet.scion_hop_fields[2].CE,      (uint16_t)452, "hop[2] ConsEgress=452");
        check_eq(packet.scion_hop_fields[2].Exptime, (uint8_t)63,   "hop[2] Exptime=63");

        std::cout << std::endl;
    }

    
    // ── Test 5: real but wrong SCION packet ────────────────
    {
        std::cout << "Test 5: real but wrong SCION packet" << std::endl;

        std::vector<uint8_t> pkt = {
            // SCION Common  Header
            0, 0, 0, 1, 17, 24, 0, 113, 1, 3, 0, 0,
            // SCION Address Header
            // Dst ISD and AS
            0, 2, 255, 0, 0, 0, 2, 16,
            // Src ISD and AS
            0, 2, 255, 0, 0, 0, 2, 34, 
            // DstHostAdr
            127, 0, 0, 119, 
            // SrcHostAdr
            253, 0, 240, 13, 202, 254, 0, 0, 0, 0, 0, 0, 127, 0, 0, 85, 
            //Path Meta Header (SegLen0 = ?, SegLen1 = ?, SegLen2 = 0?)
            0, 0, 48, 0,
            // Info Field 0
            0, 0, 243, 145, 106, 11, 107, 16, 
            // HopField 0
            0, 63, 1, 45, 0, 0, 126, 219, 66, 222, 126, 2,
            // HopField 1
            //0, 63, 0, 8, 0, 4, 171, 146, 47, 51, 222, 25,
            // HopField 2 
            //0, 63, 0, 0, 1, 196, 16, 193, 164, 132, 129, 60,
            // Other headers and payload(?)
            /*127, 254, 127, 255, 0, 113, 77, 29, 123, 34, 115, 101, 114, 118, 101,
            114, 34, 58, 34, 50, 45, 102, 102, 48, 48, 58, 48, 58, 50, 49, 48, 34, 
            44, 34, 109, 101, 115, 115, 97, 103, 101, 34, 58, 34, 112, 105, 110, 103, 
            34, 44, 34, 116, 114, 97, 99, 101, 34, 58, 34, 65, 65, 65, 65, 65, 65, 65, 
            65, 65, 65, 65, 88, 114, 105, 81, 51, 98, 115, 65, 66, 50, 83, 75, 52, 110, 
            112, 98, 110, 47, 113, 77, 74, 70, 54, 52, 107, 78, 50, 55, 65, 65, 100, 107, */
            66, 65, 65, 65, 65, 65, 65, 61, 61, 34, 125 
        }; 

        std::cout << pkt.size() << std::endl;
        std::cout << 24*4 + 113 << std::endl;


        simple_packet_t packet;
        parser_options_t options;

        

        // Call parse_scion_packet directly since there is no Ethernet/IP/UDP wrapper
        parser_code_t result = parse_scion_packet(
            pkt.data(),
            pkt.data() + pkt.size(),
            packet,
            options
        );


        check(result == parser_code_t::memory_violation, "returns memory_violation");

        std::cout << std::endl;
    }

    // ── Summary ───────────────────────────────────────────────────────
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed." << std::endl;

    return tests_failed > 0 ? 1 : 0;
}