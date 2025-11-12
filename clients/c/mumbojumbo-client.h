#ifndef MUMBOJUMBO_CLIENT_H
#define MUMBOJUMBO_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_FRAG_DATA_LEN 80
#define DNS_LABEL_MAX_LEN 63
#define HEADER_SIZE 12
#define SEALED_BOX_OH 48  // 32-byte ephemeral pubkey + 16-byte tag
#define PUBLIC_KEY_SIZE 32

// Query result structure
typedef struct {
    char *query;
    bool success;
} QueryResult;

// MumbojumboClient structure
typedef struct {
    uint8_t server_pubkey[32];
    char *domain;
    size_t max_fragment_size;
    uint16_t next_packet_id;
} MumbojumboClient;

// Key parsing
int parse_key_hex(const char *key_str, uint8_t key[32]);

// Base32 encoding
char *base32_encode(const uint8_t *data, size_t len);

// DNS label splitting
char **split_to_labels(const char *data, size_t max_len, size_t *count);
void free_labels(char **labels, size_t count);

// Fragment creation
int create_fragment(uint16_t packet_id, uint32_t frag_index, uint32_t frag_count,
                   const uint8_t *frag_data, size_t frag_data_len,
                   uint8_t **out_fragment, size_t *out_len);

// Encryption
int encrypt_sealed_box(const uint8_t *plaintext, size_t plaintext_len,
                      const uint8_t recipient_pubkey[32],
                      uint8_t **out_encrypted, size_t *out_len);

// DNS query creation
char *create_dns_query(const uint8_t *encrypted, size_t encrypted_len, const char *domain);

// DNS query sending
bool send_dns_query(const char *dns_name);

// Data fragmentation
int fragment_data(const uint8_t *data, size_t data_len, size_t max_fragment_size,
                 uint8_t ***out_fragments, size_t **out_frag_lens, size_t *out_count);
void free_fragments(uint8_t **fragments, size_t *frag_lens, size_t count);

// Client API
MumbojumboClient *mumbojumbo_client_new(const uint8_t server_pubkey[32],
                                        const char *domain,
                                        size_t max_fragment_size);
void mumbojumbo_client_free(MumbojumboClient *client);

int mumbojumbo_send_data(MumbojumboClient *client, const uint8_t *data, size_t data_len,
                         bool send_queries, QueryResult **out_results, size_t *out_count);
void free_query_results(QueryResult *results, size_t count);

int mumbojumbo_generate_queries(MumbojumboClient *client, const uint8_t *data, size_t data_len,
                                char ***out_queries, size_t *out_count);
void free_queries(char **queries, size_t count);

#endif // MUMBOJUMBO_CLIENT_H
