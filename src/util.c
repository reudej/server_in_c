#include <stdlib.h>

void generate_random_string(char *buffer, int length) {
    unsigned char random_bytes[length / 2];
    RAND_bytes(random_bytes, length / 2);
    for (int i = 0; i < length / 2; i++) {
        sprintf(buffer + (i * 2), "%02x", random_bytes[i]);
    }
    buffer[length] = '\0';
}

char* sanitize_html(const char *input) {
    if (!input) return NULL;
    int len = strlen(input);
    char *output = malloc(len * 6 + 1);
    int out_pos = 0;
    for (int i = 0; i < len; i++) {
        switch (input[i]) {
            case '<': strcpy(output + out_pos, "&lt;"); out_pos += 4; break;
            case '>': strcpy(output + out_pos, "&gt;"); out_pos += 4; break;
            case '&': strcpy(output + out_pos, "&amp;"); out_pos += 5; break;
            case '"': strcpy(output + out_pos, "&quot;"); out_pos += 6; break;
            case '\'': strcpy(output + out_pos, "&#x27;"); out_pos += 6; break;
            default: output[out_pos++] = input[i]; break;
        }
    }
    output[out_pos] = '\0';
    return output;
}
