#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qrencode.h>

#define BLACK "\033[40m  \033[0m"
#define WHITE "\033[47m  \033[0m"

void print_qr_ascii(const char *text) {
    QRcode *qrcode = QRcode_encodeString8bit(text, 0, QR_ECLEVEL_L);
    if (!qrcode) {
        fprintf(stderr, "Failed to encode QR code\n");
        return;
    }

    int size = qrcode->width;
    unsigned char *data = qrcode->data;

    // Top margin
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < size + 4; ++j) printf(WHITE);
        printf("\n");
    }

    for (int y = 0; y < size; ++y) {
        // Left margin
        printf(WHITE); printf(WHITE);
        for (int x = 0; x < size; ++x) {
            printf((data[y * size + x] & 1) ? BLACK : WHITE);
        }
        // Right margin
        printf(WHITE); printf(WHITE);
        printf("\n");
    }

    // Bottom margin
    for (int i = 0; i < 2; ++i) {
        for (int j = 0; j < size + 4; ++j) printf(WHITE);
        printf("\n");
    }

    QRcode_free(qrcode);
}
