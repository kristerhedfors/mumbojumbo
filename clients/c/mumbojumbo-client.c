#include "mumbojumbo-client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sodium.h>

// Parse key in mj_pub_<hex> format
int parse_key_hex(const char *key_str, uint8_t key[32]) {
    if (strncmp(key_str, "mj_pub_", 7) != 0) {
        fprintf(stderr, "Error: key must start with \"mj_pub_\"\n");
        return -1;
    }

    const char *hex_key = key_str + 7;
    if (strlen(hex_key) != 64) {
        fprintf(stderr, "Error: invalid hex key length: expected 64, got %zu\n", strlen(hex_key));
        return -1;
    }

    // Decode hex
    for (size_t i = 0; i < 32; i++) {
        int hi = hex_key[i * 2];
        int lo = hex_key[i * 2 + 1];

        if (!isxdigit(hi) || !isxdigit(lo)) {
            fprintf(stderr, "Error: invalid hex characters in key\n");
            return -1;
        }

        hi = isdigit(hi) ? (hi - '0') : (tolower(hi) - 'a' + 10);
        lo = isdigit(lo) ? (lo - '0') : (tolower(lo) - 'a' + 10);

        key[i] = (hi << 4) | lo;
    }

    return 0;
}

// Base32 encode (lowercase, no padding)
char *base32_encode(const uint8_t *data, size_t len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    if (len == 0) {
        char *result = malloc(1);
        result[0] = '\0';
        return result;
    }

    // Calculate output size (ceil(len * 8 / 5))
    size_t output_len = ((len * 8) + 4) / 5;
    char *output = malloc(output_len + 1);
    if (!output) return NULL;

    uint32_t bits = 0;
    uint32_t value = 0;
    size_t pos = 0;

    for (size_t i = 0; i < len; i++) {
        value = (value << 8) | data[i];
        bits += 8;

        while (bits >= 5) {
            output[pos++] = alphabet[(value >> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output[pos++] = alphabet[(value << (5 - bits)) & 31];
    }

    output[pos] = '\0';

    // Convert to lowercase
    for (size_t i = 0; i < pos; i++) {
        output[i] = tolower(output[i]);
    }

    return output;
}

// Split string into DNS labels of max length
char **split_to_labels(const char *data, size_t max_len, size_t *count) {
    size_t data_len = strlen(data);

    if (data_len == 0) {
        *count = 0;
        return NULL;
    }

    *count = (data_len + max_len - 1) / max_len;
    char **labels = malloc(*count * sizeof(char *));
    if (!labels) return NULL;

    size_t pos = 0;
    for (size_t i = 0; i < *count; i++) {
        size_t chunk_len = (pos + max_len <= data_len) ? max_len : (data_len - pos);
        labels[i] = malloc(chunk_len + 1);
        if (!labels[i]) {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                free(labels[j]);
            }
            free(labels);
            return NULL;
        }
        memcpy(labels[i], data + pos, chunk_len);
        labels[i][chunk_len] = '\0';
        pos += chunk_len;
    }

    return labels;
}

void free_labels(char **labels, size_t count) {
    if (!labels) return;
    for (size_t i = 0; i < count; i++) {
        free(labels[i]);
    }
    free(labels);
}

// Create fragment with 12-byte header
int create_fragment(uint16_t packet_id, uint32_t frag_index, uint32_t frag_count,
                   const uint8_t *frag_data, size_t frag_data_len,
                   uint8_t **out_fragment, size_t *out_len) {
    if (frag_index >= frag_count) {
        fprintf(stderr, "Error: invalid frag_index %u for frag_count %u\n", frag_index, frag_count);
        return -1;
    }

    if (frag_data_len > MAX_FRAG_DATA_LEN) {
        fprintf(stderr, "Error: fragment data too large: %zu > %d\n", frag_data_len, MAX_FRAG_DATA_LEN);
        return -1;
    }

    *out_len = HEADER_SIZE + frag_data_len;
    *out_fragment = malloc(*out_len);
    if (!*out_fragment) return -1;

    uint8_t *header = *out_fragment;

    // Packet ID (big-endian u16)
    header[0] = (packet_id >> 8) & 0xFF;
    header[1] = packet_id & 0xFF;

    // Frag index (big-endian u32)
    header[2] = (frag_index >> 24) & 0xFF;
    header[3] = (frag_index >> 16) & 0xFF;
    header[4] = (frag_index >> 8) & 0xFF;
    header[5] = frag_index & 0xFF;

    // Frag count (big-endian u32)
    header[6] = (frag_count >> 24) & 0xFF;
    header[7] = (frag_count >> 16) & 0xFF;
    header[8] = (frag_count >> 8) & 0xFF;
    header[9] = frag_count & 0xFF;

    // Data length (big-endian u16)
    header[10] = (frag_data_len >> 8) & 0xFF;
    header[11] = frag_data_len & 0xFF;

    // Copy fragment data
    if (frag_data_len > 0) {
        memcpy(header + HEADER_SIZE, frag_data, frag_data_len);
    }

    return 0;
}

// Encrypt using libsodium's crypto_box_seal (SealedBox)
int encrypt_sealed_box(const uint8_t *plaintext, size_t plaintext_len,
                      const uint8_t recipient_pubkey[32],
                      uint8_t **out_encrypted, size_t *out_len) {
    *out_len = crypto_box_SEALBYTES + plaintext_len;
    *out_encrypted = malloc(*out_len);
    if (!*out_encrypted) return -1;

    if (crypto_box_seal(*out_encrypted, plaintext, plaintext_len, recipient_pubkey) != 0) {
        free(*out_encrypted);
        *out_encrypted = NULL;
        return -1;
    }

    return 0;
}

// Create DNS query name from encrypted data
char *create_dns_query(const uint8_t *encrypted, size_t encrypted_len, const char *domain) {
    char *b32 = base32_encode(encrypted, encrypted_len);
    if (!b32) return NULL;

    size_t label_count;
    char **labels = split_to_labels(b32, DNS_LABEL_MAX_LEN, &label_count);
    free(b32);

    if (!labels && label_count > 0) return NULL;

    // Calculate total length
    size_t total_len = strlen(domain);
    for (size_t i = 0; i < label_count; i++) {
        total_len += strlen(labels[i]) + 1; // +1 for dot
    }

    char *result = malloc(total_len + 1);
    if (!result) {
        free_labels(labels, label_count);
        return NULL;
    }

    // Join labels with dots
    size_t pos = 0;
    for (size_t i = 0; i < label_count; i++) {
        size_t len = strlen(labels[i]);
        memcpy(result + pos, labels[i], len);
        pos += len;
        result[pos++] = '.';
    }

    // Remove trailing dot if present
    if (pos > 0 && result[pos - 1] == '.') {
        pos--;
    }

    // Append domain
    strcpy(result + pos, domain);

    free_labels(labels, label_count);
    return result;
}

// Send DNS query using dig command
bool send_dns_query(const char *dns_name) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "dig +short '%s' >/dev/null 2>&1", dns_name);
    return system(cmd) == 0;
}

// Fragment data into chunks
int fragment_data(const uint8_t *data, size_t data_len, size_t max_fragment_size,
                 uint8_t ***out_fragments, size_t **out_frag_lens, size_t *out_count) {
    if (data_len == 0) {
        *out_count = 1;
        *out_fragments = malloc(sizeof(uint8_t *));
        *out_frag_lens = malloc(sizeof(size_t));
        if (!*out_fragments || !*out_frag_lens) return -1;

        (*out_fragments)[0] = malloc(0);
        (*out_frag_lens)[0] = 0;
        return 0;
    }

    *out_count = (data_len + max_fragment_size - 1) / max_fragment_size;
    *out_fragments = malloc(*out_count * sizeof(uint8_t *));
    *out_frag_lens = malloc(*out_count * sizeof(size_t));

    if (!*out_fragments || !*out_frag_lens) return -1;

    size_t pos = 0;
    for (size_t i = 0; i < *out_count; i++) {
        size_t chunk_len = (pos + max_fragment_size <= data_len) ? max_fragment_size : (data_len - pos);
        (*out_frag_lens)[i] = chunk_len;
        (*out_fragments)[i] = malloc(chunk_len);
        if (!(*out_fragments)[i]) return -1;

        memcpy((*out_fragments)[i], data + pos, chunk_len);
        pos += chunk_len;
    }

    return 0;
}

void free_fragments(uint8_t **fragments, size_t *frag_lens, size_t count) {
    if (!fragments) return;
    for (size_t i = 0; i < count; i++) {
        free(fragments[i]);
    }
    free(fragments);
    free(frag_lens);
}

// Create new client instance
MumbojumboClient *mumbojumbo_client_new(const uint8_t server_pubkey[32],
                                        const char *domain,
                                        size_t max_fragment_size) {
    MumbojumboClient *client = malloc(sizeof(MumbojumboClient));
    if (!client) return NULL;

    memcpy(client->server_pubkey, server_pubkey, 32);

    // Auto-prepend dot to domain if needed
    if (domain[0] == '.') {
        client->domain = strdup(domain);
    } else {
        client->domain = malloc(strlen(domain) + 2);
        sprintf(client->domain, ".%s", domain);
    }

    client->max_fragment_size = max_fragment_size;

    // Initialize with random packet ID
    randombytes_buf(&client->next_packet_id, sizeof(client->next_packet_id));

    return client;
}

void mumbojumbo_client_free(MumbojumboClient *client) {
    if (!client) return;
    free(client->domain);
    free(client);
}

// Send data via DNS queries
int mumbojumbo_send_data(MumbojumboClient *client, const uint8_t *data, size_t data_len,
                         bool send_queries, QueryResult **out_results, size_t *out_count) {
    uint16_t packet_id = client->next_packet_id;
    client->next_packet_id = (client->next_packet_id + 1) & 0xFFFF;

    uint8_t **fragments;
    size_t *frag_lens;
    size_t frag_count;

    if (fragment_data(data, data_len, client->max_fragment_size, &fragments, &frag_lens, &frag_count) != 0) {
        return -1;
    }

    *out_count = frag_count;
    *out_results = malloc(frag_count * sizeof(QueryResult));
    if (!*out_results) {
        free_fragments(fragments, frag_lens, frag_count);
        return -1;
    }

    for (size_t i = 0; i < frag_count; i++) {
        // Create fragment with header
        uint8_t *plaintext;
        size_t plaintext_len;

        if (create_fragment(packet_id, i, frag_count, fragments[i], frag_lens[i],
                          &plaintext, &plaintext_len) != 0) {
            free_fragments(fragments, frag_lens, frag_count);
            free_query_results(*out_results, i);
            return -1;
        }

        // Encrypt with SealedBox
        uint8_t *encrypted;
        size_t encrypted_len;

        if (encrypt_sealed_box(plaintext, plaintext_len, client->server_pubkey,
                              &encrypted, &encrypted_len) != 0) {
            free(plaintext);
            free_fragments(fragments, frag_lens, frag_count);
            free_query_results(*out_results, i);
            return -1;
        }

        free(plaintext);

        // Create DNS query name
        char *dns_name = create_dns_query(encrypted, encrypted_len, client->domain);
        free(encrypted);

        if (!dns_name) {
            free_fragments(fragments, frag_lens, frag_count);
            free_query_results(*out_results, i);
            return -1;
        }

        // Optionally send query
        bool success = send_queries ? send_dns_query(dns_name) : true;

        (*out_results)[i].query = dns_name;
        (*out_results)[i].success = success;
    }

    free_fragments(fragments, frag_lens, frag_count);
    return 0;
}

void free_query_results(QueryResult *results, size_t count) {
    if (!results) return;
    for (size_t i = 0; i < count; i++) {
        free(results[i].query);
    }
    free(results);
}

// Generate queries without sending
int mumbojumbo_generate_queries(MumbojumboClient *client, const uint8_t *data, size_t data_len,
                                char ***out_queries, size_t *out_count) {
    QueryResult *results;
    if (mumbojumbo_send_data(client, data, data_len, false, &results, out_count) != 0) {
        return -1;
    }

    *out_queries = malloc(*out_count * sizeof(char *));
    if (!*out_queries) {
        free_query_results(results, *out_count);
        return -1;
    }

    for (size_t i = 0; i < *out_count; i++) {
        (*out_queries)[i] = results[i].query;
        results[i].query = NULL; // Transfer ownership
    }

    free_query_results(results, *out_count);
    return 0;
}

void free_queries(char **queries, size_t count) {
    if (!queries) return;
    for (size_t i = 0; i < count; i++) {
        free(queries[i]);
    }
    free(queries);
}

// CLI implementation
static void print_usage(void) {
    fprintf(stderr,
        "\n"
        "Mumbojumbo DNS Client - C Implementation\n"
        "\n"
        "Usage: mumbojumbo-client -k <key> -d <domain> [options]\n"
        "\n"
        "Required arguments:\n"
        "  -k <public_key>     Server public key (mj_pub_... format)\n"
        "  -d <domain>         DNS domain suffix (e.g., .asd.qwe)\n"
        "\n"
        "Optional arguments:\n"
        "  -f <path>           Input file path (use \"-\" for stdin, default: stdin)\n"
        "  -v                  Enable verbose output to stderr\n"
        "  -h                  Show this help message\n"
        "\n"
        "Examples:\n"
        "  echo \"Hello\" | mumbojumbo-client -k mj_pub_abc123... -d .asd.qwe\n"
        "  mumbojumbo-client -k mj_pub_abc123... -d .asd.qwe -f message.txt\n"
        "  mumbojumbo-client -k mj_pub_abc123... -d .asd.qwe -v\n"
        "\n"
    );
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: failed to initialize libsodium\n");
        return 1;
    }

    char *key_str = NULL;
    char *domain = NULL;
    char *file_path = NULL;
    bool verbose = false;

    // Parse arguments
    int opt;
    while ((opt = getopt(argc, argv, "k:d:f:vh")) != -1) {
        switch (opt) {
            case 'k':
                key_str = optarg;
                break;
            case 'd':
                domain = optarg;
                break;
            case 'f':
                file_path = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    if (!key_str || !domain) {
        fprintf(stderr, "Error: -k and -d are required\n");
        fprintf(stderr, "Use -h for usage information\n");
        return 1;
    }

    // Parse server public key
    uint8_t server_pubkey[32];
    if (parse_key_hex(key_str, server_pubkey) != 0) {
        return 1;
    }

    // Validate domain
    if (domain[0] != '.') {
        fprintf(stderr, "Warning: domain should start with '.', got '%s'\n", domain);
        fprintf(stderr, "         Prepending '.' automatically\n");
    }

    // Read input data
    uint8_t *data = NULL;
    size_t data_len = 0;
    size_t data_cap = 4096;

    FILE *input = stdin;
    if (file_path && strcmp(file_path, "-") != 0) {
        input = fopen(file_path, "rb");
        if (!input) {
            fprintf(stderr, "Error: failed to open file '%s'\n", file_path);
            return 1;
        }
    }

    data = malloc(data_cap);
    if (!data) {
        fprintf(stderr, "Error: memory allocation failed\n");
        if (input != stdin) fclose(input);
        return 1;
    }

    size_t n;
    while ((n = fread(data + data_len, 1, data_cap - data_len, input)) > 0) {
        data_len += n;
        if (data_len == data_cap) {
            data_cap *= 2;
            uint8_t *new_data = realloc(data, data_cap);
            if (!new_data) {
                fprintf(stderr, "Error: memory allocation failed\n");
                free(data);
                if (input != stdin) fclose(input);
                return 1;
            }
            data = new_data;
        }
    }

    if (input != stdin) fclose(input);

    if (verbose) {
        fprintf(stderr, "Read %zu bytes of input\n", data_len);
    }

    // Create client
    MumbojumboClient *client = mumbojumbo_client_new(server_pubkey, domain, MAX_FRAG_DATA_LEN);
    if (!client) {
        fprintf(stderr, "Error: failed to create client\n");
        free(data);
        return 1;
    }

    if (verbose) {
        size_t frag_count = (data_len + MAX_FRAG_DATA_LEN - 1) / MAX_FRAG_DATA_LEN;
        if (data_len == 0) frag_count = 1;
        fprintf(stderr, "Split into %zu fragment(s)\n\n", frag_count);
    }

    // Send data
    QueryResult *results;
    size_t result_count;

    if (mumbojumbo_send_data(client, data, data_len, true, &results, &result_count) != 0) {
        fprintf(stderr, "Error: failed to send data\n");
        mumbojumbo_client_free(client);
        free(data);
        return 1;
    }

    // Process results
    size_t success_count = 0;
    for (size_t i = 0; i < result_count; i++) {
        // Output query for inspection
        printf("%s\n", results[i].query);

        if (results[i].success) {
            success_count++;
        }

        if (verbose) {
            fprintf(stderr, "Fragment %zu/%zu:\n", i + 1, result_count);

            // Calculate sizes for display
            size_t frag_data_len = MAX_FRAG_DATA_LEN;
            if (i == result_count - 1 && data_len % MAX_FRAG_DATA_LEN != 0) {
                frag_data_len = data_len % MAX_FRAG_DATA_LEN;
            }
            size_t plaintext_len = HEADER_SIZE + frag_data_len;
            size_t encrypted_len = plaintext_len + SEALED_BOX_OH;

            fprintf(stderr, "  Data length: %zu bytes\n", frag_data_len);
            fprintf(stderr, "  Plaintext length: %zu bytes\n", plaintext_len);
            fprintf(stderr, "  Encrypted length: %zu bytes\n", encrypted_len);
            fprintf(stderr, "  DNS name length: %zu chars\n", strlen(results[i].query));
            fprintf(stderr, "  Sending query...\n");

            if (results[i].success) {
                fprintf(stderr, "  ✓ Sent successfully\n");
            } else {
                fprintf(stderr, "  ✗ Send failed (DNS query timed out or failed)\n");
            }

            fprintf(stderr, "\n");
        }
    }

    if (verbose) {
        fprintf(stderr, "Sent %zu/%zu fragment(s) successfully\n", success_count, result_count);
    }

    int exit_code = (success_count == result_count) ? 0 : 1;

    free_query_results(results, result_count);
    mumbojumbo_client_free(client);
    free(data);

    return exit_code;
}
