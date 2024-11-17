#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <time.h>

#define MAX_PAYLOAD_SIZE 2048
#define THRESHOLD_COUNT 1000
#define IP_BLACKLIST_SIZE 100

// Structure to log attack details

typedef struct {
    int count;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char protocol[10];
} attack_entry;

// Structure to maintain a list of blacklisted IPs

typedef struct {
    char ip[INET_ADDRSTRLEN];
} ip_entry;

attack_entry attack_log[THRESHOLD_COUNT]; // Log of detected attacks
ip_entry ip_blacklist[IP_BLACKLIST_SIZE]; // List of blacklisted IP addresses
int attack_index = 0; // Index for attack log
int blacklist_index = 0; // Index for blacklist

// Function to log details of detected attacks

void log_attack_details(const char *src_ip, const char *dst_ip, const char *protocol, int packet_count) {
    if (attack_index < THRESHOLD_COUNT) {
        strcpy(attack_log[attack_index].src_ip, src_ip);
        strcpy(attack_log[attack_index].dst_ip, dst_ip);
        strcpy(attack_log[attack_index].protocol, protocol);
        attack_log[attack_index].count = packet_count;
        attack_index++;
    } else {
        printf("Attack log limit reached.\n");
    }
}

// Function to add an IP to the blacklist

void add_to_blacklist(const char *ip) {
    if (blacklist_index < IP_BLACKLIST_SIZE) {
        strcpy(ip_blacklist[blacklist_index].ip, ip);
        blacklist_index++;
        printf("IP %s added to blacklist.\n", ip);
    } else {
        printf("IP blacklist limit reached.\n");
    }
}

// Function to check if an IP is blacklisted

int is_ip_blacklisted(const char *ip) {
    for (int i = 0; i < blacklist_index; i++) {
        if (strcmp(ip_blacklist[i].ip, ip) == 0) {
            return 1; // IP is blacklisted
        }
    }
    return 0; // IP is not blacklisted
}

// Function to analyze the payload of a packet

void analyze_payload(const u_char *payload, int len) {
    printf("Analyzing payload: ");
    for (int i = 0; i < len; i++) {
        if (isprint(payload[i])) {
            printf("%c", payload[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

// Function to display the logged attacks

void display_attack_log() {
    printf("\n---- Attack Log ----\n");
    for (int i = 0; i < attack_index; i++) {
        printf("Attack %d - SRC: %s DST: %s Protocol: %s Count: %d\n", 
                i + 1, attack_log[i].src_ip, attack_log[i].dst_ip, attack_log[i].protocol, attack_log[i].count);
    }
}

// Packet handler function called for each captured packet

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *iph;
    struct tcphdr *tcph;

    iph = (struct ip *)(packet + 14); // Skipping Ethernet header

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Check if the source IP is blacklisted
    
    if (is_ip_blacklisted(src_ip)) {
        printf("Blocked packet from blacklisted IP: %s\n", src_ip);
        return; // Block the packet if the source IP is blacklisted
    }

    if (iph->ip_p == IPPROTO_TCP) {
        tcph = (struct tcphdr *)(packet + 14 + (iph->ip_hl * 4));
        printf("TCP Packet detected: %s -> %s\n", src_ip, dst_ip);
        log_attack_details(src_ip, dst_ip, "TCP", 1); // Log TCP packet details
    }

    // Calculate payload offset and length
    
    int payload_offset = 14 + (iph->ip_hl * 4) + (tcph->th_off * 4);
    int payload_len = header->caplen - payload_offset;

    // Analyze payload if present
    
    if (payload_len > 0) {
        const u_char *payload = packet + payload_offset;
        analyze_payload(payload, payload_len);
    }

    // Example of threshold-based detection
    
    if (++attack_log[attack_index - 1].count > 10) {
        add_to_blacklist(src_ip); // Blacklist if threshold exceeded
        printf("Traffic threshold exceeded for %s, added to blacklist.\n", src_ip);
    }
}

int main() {
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Find the default device for capturing packets
    
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // Open the device for packet capturing
    
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Listening on device %s...\n", dev);

    // Start capturing packets
    
    pcap_loop(handle, 0, packet_handler, NULL);

    // Clean up
    
    pcap_close(handle);
    display_attack_log(); // Display logged attack details
    return 0;
}
