/*
 * Copyright 2013 Vlad V. Ungureanu <ungureanuvladvictor@gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this Github repository and wiki except in
 * compliance with the License. You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <linux/ip.h>
#include <sys/stat.h>

#include <libusb.h>

#include "rndis.h"
#include "ether2.h"
#include "ipv4.h"
#include "udp.h"
#include "bootp.h"
#include "tftp.h"
#include "arp.h"
#include "utils.h"


#define ENDPOINT_ROM    (0x02 | LIBUSB_ENDPOINT_OUT)
#define ENDPOINT_SPL    (0x01 | LIBUSB_ENDPOINT_OUT)
#define BULK_EP_IN      (0x81 | LIBUSB_ENDPOINT_IN)
#define INT_EP_IN       (0x82 | LIBUSB_ENDPOINT_IN)


static size_t rndissize = sizeof(rndis_hdr);
static size_t ethersize = sizeof(struct ethhdr);
static size_t arpsize = sizeof(arp_hdr);
static size_t ipsize = sizeof(struct iphdr);
static size_t udpsize = sizeof(udp_t);
static size_t bootpsize = sizeof(bootp_packet);
static size_t tftpsize = sizeof(tftp_data);

static int stage;
static int finished;


static void
_init(libusb_context *ctx) {
    int rc;

    rc = libusb_init(&ctx);
    if(rc < 0) {
        printf("Init error!\n");
        exit(1);
    }

    libusb_set_debug(ctx, LIBUSB_LOG_LEVEL_INFO);
}

static void
_destroy(libusb_context *ctx) {
    libusb_exit(ctx);
}

static size_t
populate_arp_packet(struct ethhdr *eth_hdr, arp_hdr *arphdr, uint8_t *arp_packet) {
    rndis_hdr rndis;
    struct ethhdr ether;

    memset(&rndis, 0, sizeof(rndis_hdr));
    memset(&ether, 0, sizeof(struct ethhdr));

    make_rndis(&rndis, ethersize + arpsize);
    make_ether2(&ether, eth_hdr->h_source, (uint8_t*)my_hwaddr);
    ether.h_proto = htons(ETHARPP);

    memcpy(arp_packet, &rndis, rndissize);
    memcpy(arp_packet + rndissize, &ether, ethersize);
    memcpy(arp_packet + rndissize + ethersize, arphdr, arpsize);

    return rndissize + ethersize + arpsize;
}

static size_t
populate_bootp_packet(struct ethhdr *eth_hdr, uint16_t udp_dst, uint16_t udp_src, uint32_t xid, const char *name, uint8_t *arp_packet) {
    rndis_hdr rndis;
    struct ethhdr ether;
    struct iphdr ip;
    udp_t udp;
    bootp_packet bpp;

    memset(&rndis, 0, sizeof(rndis));
    memset(&ether, 0, sizeof(struct ethhdr));
    memset(&ip, 0, sizeof(struct iphdr));
    memset(&udp, 0, sizeof(udp_t));
    memset(&bpp, 0, sizeof(bootp_packet));

    make_rndis(&rndis, ethersize + ipsize + udpsize + bootpsize);
    make_ether2(&ether, eth_hdr->h_source, (uint8_t*)my_hwaddr);
    ether.h_proto = htons(ETHIPP);
    make_ipv4(&ip, server_ip, BBB_ip, IPUDP, 0, ipsize + udpsize + bootpsize);
    make_udp(&udp, bootpsize, udp_dst, udp_src);
    make_bootp(servername, name, &bpp, xid, eth_hdr->h_source);

    memcpy(arp_packet, &rndis, rndissize);
    memcpy(arp_packet + rndissize, &ether, ethersize);
    memcpy(arp_packet + rndissize + ethersize, &ip, ipsize);
    memcpy(arp_packet + rndissize + ethersize + ipsize, &udp, udpsize);
    memcpy(arp_packet + rndissize + ethersize + ipsize + udpsize, &bpp, bootpsize);

    return rndissize + ethersize + ipsize + udpsize + bootpsize;
}

static size_t
populate_tftp_packet(FILE *file, char *reader, uint8_t *tftp_packet, int blk_number, uint8_t *hw_source, uint16_t udp_dst, uint16_t udp_src) {
    tftp_data tftp;
    rndis_hdr rndis;
    struct ethhdr ether;
    struct iphdr ip;
    udp_t udp;

    memset(&rndis, 0, rndissize);
    memset(&ether, 0, sizeof(struct ethhdr));
    memset(&ip, 0, sizeof(struct iphdr));
    memset(&udp, 0, sizeof(udp_t));
    memset(&tftp, 0, sizeof(tftp_data));

    int result = fread(reader, sizeof(char), 512, file);

    make_rndis(&rndis, ethersize + ipsize + udpsize + tftpsize + result);
    make_ether2(&ether, hw_source, (uint8_t*)my_hwaddr);
    ether.h_proto = htons(ETHIPP);
    make_ipv4(&ip, server_ip, BBB_ip, IPUDP, 0, ipsize + udpsize + tftpsize + result);
    make_udp(&udp, tftpsize + result, ntohs(udp_dst), ntohs(udp_src));
    make_tftp_data(&tftp, 3, blk_number);

    memcpy(tftp_packet, &rndis, rndissize);
    memcpy(tftp_packet + rndissize, &ether, ethersize);
    memcpy(tftp_packet + rndissize + ethersize, &ip, ipsize);
    memcpy(tftp_packet + rndissize + ethersize + ipsize, &udp, udpsize);
    memcpy(tftp_packet + rndissize + ethersize + ipsize + udpsize, &tftp, tftpsize);
    memcpy(tftp_packet + rndissize + ethersize + ipsize + udpsize + tftpsize, reader, result);

    return rndissize + ethersize + ipsize + udpsize + tftpsize + result;
}

static void
tftp_send_file(libusb_device_handle *dev_handle, uint8_t ep_out, uint8_t *hw_source, uint16_t udp_dst, uint16_t udp_src, const char *file_name) {
    int transferred, blk_number = 1;
    char reader[512];
    uint8_t data[1000];
    uint8_t buf[450];
    FILE *file_send;

    file_send = fopen(file_name, "rb");

    if (file_send == NULL) {
        perror("open file wrong!\n");
    }

    while(!feof(file_send)) {
        memset(data, 0, sizeof(data));
        memset(reader, 0, sizeof(reader));
        size_t len = populate_tftp_packet(file_send, reader, data, blk_number, hw_source, udp_dst, udp_src);
        libusb_bulk_transfer(dev_handle, ep_out, data, len, &transferred, 0);
        memset(buf, 0, sizeof(buf));
        libusb_bulk_transfer(dev_handle, BULK_EP_IN, buf, sizeof(buf), &transferred, 0);
        blk_number++;
    }

    fclose(file_send);
}

static void
handle_bootp_request(libusb_device_handle *dev_handle, uint8_t endpoint, const char *name) {
    int transferred;
    int sz_bpp = rndissize + ethersize + ipsize + udpsize + bootpsize;
    uint8_t bpp[sz_bpp];
    uint8_t buf[450] = {0};
    struct ethhdr eth_hdr;
    udp_t *udp;

    memset(&eth_hdr, 0, sizeof(struct ethhdr));
    memset(bpp, 0, sz_bpp);

    /*
     * receive bootp request packet
     */
    libusb_bulk_transfer(dev_handle, BULK_EP_IN, buf, 450, &transferred, 0);
    memcpy(&eth_hdr, buf + rndissize, ethersize);
    udp = (udp_t*)(buf + rndissize + ethersize + ipsize);
    bootp_packet *bootp = (bootp_packet*)(buf + (sz_bpp - bootpsize));

    /*
     * send bootp response packet
     */
    uint16_t dst = ntohs(udp->udpDst);
    uint16_t src = ntohs(udp->udpSrc);
    size_t len = populate_bootp_packet(&eth_hdr, dst, src, ntohl(bootp->xid), name, bpp);
    libusb_bulk_transfer(dev_handle, endpoint, bpp, len, &transferred, 0);
}

static void
handle_arp_request(libusb_device_handle *dev_handle, uint8_t endpoint) {
    int transferred;
    int sz_bpp = rndissize + ethersize + ipsize + udpsize + bootpsize;
    int sz_arpp = rndissize + ethersize + arpsize;
    size_t len;
    uint8_t arp_packet[sz_arpp];
    uint8_t bpp[sz_bpp];
    uint8_t buf[sz_arpp];
    arp_hdr arphdr, *recv_arp;
    struct ethhdr eth_hdr;

    memset(&eth_hdr, 0, sizeof(struct ethhdr));
    memset(&arphdr, 0, sizeof(arp_hdr));
    memset(arp_packet, 0, sz_arpp);
    memset(bpp, 0, sz_bpp);
    memset(buf, 0, sz_arpp);

    /*
     * receive arp request
     */
    libusb_bulk_transfer(dev_handle, BULK_EP_IN, buf, sz_arpp, &transferred, 0);
    memcpy(&eth_hdr, buf + rndissize, ethersize);
    recv_arp = (arp_hdr*)(buf + rndissize + ethersize);
    make_arp(&arphdr, 2,
                (const uint8_t*)&recv_arp->hw_dest, &recv_arp->ip_dest,
                (const uint8_t*)&recv_arp->hw_source, &recv_arp->ip_source);

    /*
     * send arp reply
     */
    len = populate_arp_packet(&eth_hdr, &arphdr, arp_packet);
    libusb_bulk_transfer(dev_handle, endpoint, arp_packet, len, &transferred, 0);
}

static void
handle_tftp_request(libusb_device_handle *dev_handle, struct ethhdr *eth_hdr, udp_t *udp_hdr) {
    int transferred;
    uint8_t buf[450] = {0};

    /*
     * u-boot will send 2 arp request packets before we send fit file
     */
    do {
        libusb_bulk_transfer(dev_handle, BULK_EP_IN, buf, 450, &transferred, 0);
        memcpy(eth_hdr, buf + rndissize, ethersize);
        memcpy(udp_hdr, buf + rndissize + ethersize + ipsize, udpsize);
    } while (udp_hdr->udpDst == 0 || udp_hdr->udpSrc == 0);
}

static void
transfer_boot(libusb_device_handle *handle, uint8_t endpoint, const char *name, const char *tip) {
    struct ethhdr eth_hdr;
    udp_t udp;

    memset(&eth_hdr, 0, sizeof(struct ethhdr));
    memset(&udp, 0, sizeof(udp_t));

    printf(" %s\n\n", tip);

    handle_bootp_request(handle, endpoint, name);
    handle_arp_request(handle, endpoint);
    handle_tftp_request(handle, &eth_hdr, &udp);

    if (udp.udpDst == 0 || udp.udpSrc == 0) {
        printf("Receive UDP packet failed.\n");
        exit(EXIT_FAILURE);
    }

    tftp_send_file(handle, endpoint, eth_hdr.h_source, udp.udpDst, udp.udpSrc, name);
}

static int
hotplug_callback(libusb_context *ctx, libusb_device *dev, libusb_hotplug_event event, void *user_data) {
    int rc;
    struct libusb_device_descriptor desc;
    libusb_device_handle *handle = NULL;

    rc = libusb_get_device_descriptor(dev, &desc);
    if (LIBUSB_SUCCESS != rc) {
        fprintf(stderr, "Error getting device descriptor\n");
    }

    if (LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED == event) {
        if (stage++ > 0) {
            sleep(1);
        }

        libusb_open(dev, &handle);
        rc = libusb_kernel_driver_active(handle, 0);
        if(rc) {
            libusb_detach_kernel_driver(handle, 0);
        }
        rc = libusb_claim_interface(handle, 1);
        if(rc) {
            printf("Cannot Claim Interface: %s\n", libusb_error_name(rc));
            exit(1);
        }

        if (desc.idVendor == ROMVID && desc.idProduct == ROMPID) {
            transfer_boot(handle, ENDPOINT_ROM, "spl", "ROM has started!");
        }
        if (desc.idVendor == SPLVID && desc.idProduct == SPLPID) {
            transfer_boot(handle, ENDPOINT_SPL, "uboot", "SPL has started!");
        }
        if (desc.idVendor == UBOOTVID && desc.idProduct == UBOOTPID) {
            transfer_boot(handle, ENDPOINT_SPL, "fit", "U-Boot has started! Sending now the FIT image!");
        }

        rc = libusb_release_interface(handle, 1);
        if(rc) {
            printf("Cannot release interface: %s\n", libusb_error_name(rc));
        }
        libusb_close(handle);

    } else if (LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT == event) {
        if (stage > 0 && desc.idVendor == UBOOTVID && desc.idProduct == UBOOTPID) {
            finished = 1;
        }

    } else {
        printf("Unsupported event %d\n", event);
    }

    return 0;
}

int
main(int argc, const char *argv[]) {
    int rc;
    libusb_context *ctx = NULL;
    libusb_hotplug_callback_handle handles[3];

    _init(ctx);

    if (!libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG)) {
        printf("Hotplug not supported by this build of libusb\n");
        libusb_exit (NULL);
        return EXIT_FAILURE;
    }

    rc = libusb_hotplug_register_callback(ctx,
      LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
      0, ROMVID, ROMPID, LIBUSB_HOTPLUG_MATCH_ANY, hotplug_callback, NULL, &handles[0]);

    rc = libusb_hotplug_register_callback(ctx,
      LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
      0, SPLVID, SPLPID, LIBUSB_HOTPLUG_MATCH_ANY, hotplug_callback, NULL, &handles[1]);

    rc = libusb_hotplug_register_callback(ctx,
      LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
      0, UBOOTVID, UBOOTPID, LIBUSB_HOTPLUG_MATCH_ANY, hotplug_callback, NULL, &handles[2]);

    if (LIBUSB_SUCCESS != rc) {
        fprintf(stderr, "Error registering callback 0\n");
        libusb_exit(NULL);
        return EXIT_FAILURE;
    }

    while (!finished) {
        rc = libusb_handle_events(ctx);
        if (rc) {
			printf("libusb_handle_events() failed: %s\n", libusb_error_name(rc));
        }
    }

    _destroy(ctx);

    return 0;
}
