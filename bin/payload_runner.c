/*
 * Lyussfyuring002 :: payload_runner.c
 * minimal shellcode loader for proof-of-concept binary analysis
 * compile: gcc -o bin/payload_runner bin/payload_runner.c -Wall -Wextra
 * target: Arch Linux / Kali Linux (x86_64)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#define MAX_PAYLOAD 4096

typedef struct {
    uint8_t  magic[4];   /* LYU\x00 */
    uint32_t version;
    uint32_t payload_len;
    uint8_t  checksum;
    uint8_t  reserved[3];
} PayloadHeader;

static uint8_t calc_checksum(const uint8_t *buf, size_t len) {
    uint8_t cs = 0;
    for (size_t i = 0; i < len; i++) cs ^= buf[i];
    return cs;
}

static int validate_header(const PayloadHeader *hdr, size_t file_size) {
    if (memcmp(hdr->magic, "LYU\x00", 4) != 0) {
        fprintf(stderr, "[x] invalid magic bytes\n");
        return -1;
    }
    if (hdr->version != 1) {
        fprintf(stderr, "[x] unsupported version: %u\n", hdr->version);
        return -1;
    }
    if (hdr->payload_len == 0 || hdr->payload_len > MAX_PAYLOAD) {
        fprintf(stderr, "[x] payload length out of range: %u\n", hdr->payload_len);
        return -1;
    }
    if (file_size < sizeof(PayloadHeader) + hdr->payload_len) {
        fprintf(stderr, "[x] file too small for declared payload\n");
        return -1;
    }
    return 0;
}

static void hexdump(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n  %04zx: ", i);
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: payload_runner <payload_file> [--dump]\n");
        return 1;
    }

    int dump_only = (argc >= 3 && strcmp(argv[2], "--dump") == 0);

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "[x] cannot open: %s (%s)\n", argv[1], strerror(errno));
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    if (file_size < (long)sizeof(PayloadHeader)) {
        fprintf(stderr, "[x] file too small\n");
        fclose(fp);
        return 1;
    }

    uint8_t *raw = malloc((size_t)file_size);
    if (!raw) {
        fprintf(stderr, "[x] malloc failed\n");
        fclose(fp);
        return 1;
    }

    if (fread(raw, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "[x] read error\n");
        free(raw);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    PayloadHeader *hdr     = (PayloadHeader *)raw;
    uint8_t       *payload = raw + sizeof(PayloadHeader);

    if (validate_header(hdr, (size_t)file_size) != 0) {
        free(raw);
        return 1;
    }

    uint8_t cs = calc_checksum(payload, hdr->payload_len);
    if (cs != hdr->checksum) {
        fprintf(stderr, "[x] checksum mismatch: got %02x expected %02x\n", cs, hdr->checksum);
        free(raw);
        return 1;
    }

    printf("[*] payload_runner v1\n");
    printf("[*] file    : %s\n", argv[1]);
    printf("[*] version : %u\n", hdr->version);
    printf("[*] length  : %u bytes\n", hdr->payload_len);
    printf("[*] checksum: %02x (valid)\n", hdr->checksum);

    if (dump_only) {
        printf("[*] hexdump:");
        hexdump(payload, hdr->payload_len);
        free(raw);
        return 0;
    }

    /* mmap an executable region and run the shellcode */
    void *mem = mmap(NULL, hdr->payload_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "[x] mmap failed: %s\n", strerror(errno));
        free(raw);
        return 1;
    }

    memcpy(mem, payload, hdr->payload_len);
    printf("[*] executing payload at %p\n", mem);

    ((void (*)(void))mem)();

    munmap(mem, hdr->payload_len);
    free(raw);
    return 0;
}
