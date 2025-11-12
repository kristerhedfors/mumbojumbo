#include "mumbojumbo-client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAILED: %s\n", msg); \
        return 0; \
    } \
} while(0)

#define RUN_TEST(test) do { \
    printf("Running %s... ", #test); \
    if (test()) { \
        printf("PASSED\n"); \
        passed++; \
    } else { \
        printf("FAILED\n"); \
        failed++; \
    } \
    total++; \
} while(0)

// Test: Key Parsing
static int test_parse_valid_hex_key(void) {
    uint8_t key[32];
    char valid_key[72];
    strcpy(valid_key, "mj_pub_");
    for (int i = 0; i < 64; i++) {
        strcat(valid_key, "a");
    }

    ASSERT(parse_key_hex(valid_key, key) == 0, "parse_key_hex should succeed");
    ASSERT(key[0] == 0xaa, "first byte should be 0xaa");
    return 1;
}

static int test_reject_key_without_prefix(void) {
    uint8_t key[32];
    char invalid_key[65];
    for (int i = 0; i < 64; i++) {
        invalid_key[i] = 'a';
    }
    invalid_key[64] = '\0';

    ASSERT(parse_key_hex(invalid_key, key) != 0, "should reject key without prefix");
    return 1;
}

static int test_reject_key_with_wrong_length(void) {
    uint8_t key[32];
    ASSERT(parse_key_hex("mj_pub_aabbccdd", key) != 0, "should reject short key");
    return 1;
}

// Test: Base32 Encoding
static int test_base32_encode_basic(void) {
    const uint8_t data[] = "hello";
    char *encoded = base32_encode(data, 5);
    ASSERT(encoded != NULL, "encoding should succeed");
    ASSERT(strcmp(encoded, "nbswy3dp") == 0, "encoding should match expected");
    free(encoded);
    return 1;
}

static int test_base32_encode_empty(void) {
    char *encoded = base32_encode(NULL, 0);
    ASSERT(encoded != NULL, "encoding empty should succeed");
    ASSERT(strlen(encoded) == 0, "encoding empty should return empty string");
    free(encoded);
    return 1;
}

static int test_base32_encode_lowercase(void) {
    const uint8_t data[] = "TEST";
    char *encoded = base32_encode(data, 4);
    ASSERT(encoded != NULL, "encoding should succeed");

    for (size_t i = 0; encoded[i]; i++) {
        ASSERT(encoded[i] == tolower(encoded[i]), "should be lowercase");
    }

    free(encoded);
    return 1;
}

static int test_base32_encode_no_padding(void) {
    const uint8_t data[] = "hello world";
    char *encoded = base32_encode(data, 11);
    ASSERT(encoded != NULL, "encoding should succeed");
    ASSERT(strchr(encoded, '=') == NULL, "should not contain padding");
    free(encoded);
    return 1;
}

// Test: DNS Label Splitting
static int test_split_to_labels_short(void) {
    size_t count;
    char **labels = split_to_labels("abc", DNS_LABEL_MAX_LEN, &count);
    ASSERT(count == 1, "should have 1 label");
    ASSERT(strcmp(labels[0], "abc") == 0, "label should match");
    free_labels(labels, count);
    return 1;
}

static int test_split_to_labels_exact_63(void) {
    char data[64];
    memset(data, 'a', 63);
    data[63] = '\0';

    size_t count;
    char **labels = split_to_labels(data, DNS_LABEL_MAX_LEN, &count);
    ASSERT(count == 1, "should have 1 label");
    ASSERT(strlen(labels[0]) == 63, "label should be 63 chars");
    free_labels(labels, count);
    return 1;
}

static int test_split_to_labels_long(void) {
    char data[101];
    memset(data, 'a', 100);
    data[100] = '\0';

    size_t count;
    char **labels = split_to_labels(data, DNS_LABEL_MAX_LEN, &count);
    ASSERT(count == 2, "should have 2 labels");
    ASSERT(strlen(labels[0]) == 63, "first label should be 63 chars");
    ASSERT(strlen(labels[1]) == 37, "second label should be 37 chars");
    free_labels(labels, count);
    return 1;
}

static int test_split_to_labels_empty(void) {
    size_t count;
    char **labels = split_to_labels("", DNS_LABEL_MAX_LEN, &count);
    ASSERT(count == 0, "should have 0 labels");
    ASSERT(labels == NULL, "should return NULL");
    return 1;
}

// Test: Fragment Creation
static int test_create_basic_fragment(void) {
    const uint8_t frag_data[] = "test";
    uint8_t *frag;
    size_t frag_len;

    ASSERT(create_fragment(100, 0, 1, frag_data, 4, &frag, &frag_len) == 0, "fragment creation should succeed");
    ASSERT(frag_len == HEADER_SIZE + 4, "fragment length should be correct");

    uint16_t packet_id = (frag[0] << 8) | frag[1];
    uint32_t frag_index = (frag[2] << 24) | (frag[3] << 16) | (frag[4] << 8) | frag[5];
    uint32_t frag_count = (frag[6] << 24) | (frag[7] << 16) | (frag[8] << 8) | frag[9];
    uint16_t data_len = (frag[10] << 8) | frag[11];

    ASSERT(packet_id == 100, "packet_id should be 100");
    ASSERT(frag_index == 0, "frag_index should be 0");
    ASSERT(frag_count == 1, "frag_count should be 1");
    ASSERT(data_len == 4, "data_len should be 4");
    ASSERT(memcmp(frag + HEADER_SIZE, frag_data, 4) == 0, "fragment data should match");

    free(frag);
    return 1;
}

static int test_create_empty_fragment(void) {
    uint8_t *frag;
    size_t frag_len;

    ASSERT(create_fragment(1, 0, 1, NULL, 0, &frag, &frag_len) == 0, "empty fragment creation should succeed");
    ASSERT(frag_len == HEADER_SIZE, "empty fragment length should be HEADER_SIZE");

    uint16_t data_len = (frag[10] << 8) | frag[11];
    ASSERT(data_len == 0, "data_len should be 0");

    free(frag);
    return 1;
}

static int test_reject_oversized_fragment(void) {
    uint8_t oversized[MAX_FRAG_DATA_LEN + 1];
    uint8_t *frag;
    size_t frag_len;

    ASSERT(create_fragment(1, 0, 1, oversized, sizeof(oversized), &frag, &frag_len) != 0,
           "should reject oversized fragment");
    return 1;
}

static int test_reject_invalid_frag_index(void) {
    const uint8_t data[] = "test";
    uint8_t *frag;
    size_t frag_len;

    ASSERT(create_fragment(1, 5, 5, data, 4, &frag, &frag_len) != 0,
           "should reject invalid frag_index");
    return 1;
}

// Test: Data Fragmentation
static int test_fragment_small_data(void) {
    const uint8_t data[] = "small";
    uint8_t **fragments;
    size_t *frag_lens;
    size_t count;

    ASSERT(fragment_data(data, 5, MAX_FRAG_DATA_LEN, &fragments, &frag_lens, &count) == 0,
           "fragmentation should succeed");
    ASSERT(count == 1, "should have 1 fragment");
    ASSERT(frag_lens[0] == 5, "fragment should be 5 bytes");
    ASSERT(memcmp(fragments[0], data, 5) == 0, "fragment data should match");

    free_fragments(fragments, frag_lens, count);
    return 1;
}

static int test_fragment_exact_max_size(void) {
    uint8_t data[MAX_FRAG_DATA_LEN];
    memset(data, 0x42, MAX_FRAG_DATA_LEN);

    uint8_t **fragments;
    size_t *frag_lens;
    size_t count;

    ASSERT(fragment_data(data, MAX_FRAG_DATA_LEN, MAX_FRAG_DATA_LEN, &fragments, &frag_lens, &count) == 0,
           "fragmentation should succeed");
    ASSERT(count == 1, "should have 1 fragment");
    ASSERT(frag_lens[0] == MAX_FRAG_DATA_LEN, "fragment should be MAX_FRAG_DATA_LEN");

    free_fragments(fragments, frag_lens, count);
    return 1;
}

static int test_fragment_overflow(void) {
    uint8_t data[MAX_FRAG_DATA_LEN + 10];
    memset(data, 0x42, sizeof(data));

    uint8_t **fragments;
    size_t *frag_lens;
    size_t count;

    ASSERT(fragment_data(data, sizeof(data), MAX_FRAG_DATA_LEN, &fragments, &frag_lens, &count) == 0,
           "fragmentation should succeed");
    ASSERT(count == 2, "should have 2 fragments");
    ASSERT(frag_lens[0] == MAX_FRAG_DATA_LEN, "first fragment should be MAX_FRAG_DATA_LEN");
    ASSERT(frag_lens[1] == 10, "second fragment should be 10");

    free_fragments(fragments, frag_lens, count);
    return 1;
}

static int test_fragment_empty_data(void) {
    uint8_t **fragments;
    size_t *frag_lens;
    size_t count;

    ASSERT(fragment_data(NULL, 0, MAX_FRAG_DATA_LEN, &fragments, &frag_lens, &count) == 0,
           "empty fragmentation should succeed");
    ASSERT(count == 1, "should have 1 fragment");
    ASSERT(frag_lens[0] == 0, "fragment should be empty");

    free_fragments(fragments, frag_lens, count);
    return 1;
}

// Test: Client API
static int test_initialize_client(void) {
    uint8_t pubkey[32];
    memset(pubkey, 0xaa, 32);

    MumbojumboClient *client = mumbojumbo_client_new(pubkey, ".asd.qwe", MAX_FRAG_DATA_LEN);
    ASSERT(client != NULL, "client creation should succeed");
    ASSERT(strcmp(client->domain, ".asd.qwe") == 0, "domain should match");
    ASSERT(client->max_fragment_size == MAX_FRAG_DATA_LEN, "max_fragment_size should match");

    mumbojumbo_client_free(client);
    return 1;
}

static int test_auto_prepend_dot_to_domain(void) {
    uint8_t pubkey[32];
    memset(pubkey, 0xaa, 32);

    MumbojumboClient *client = mumbojumbo_client_new(pubkey, "asd.qwe", MAX_FRAG_DATA_LEN);
    ASSERT(client != NULL, "client creation should succeed");
    ASSERT(strcmp(client->domain, ".asd.qwe") == 0, "domain should have prepended dot");

    mumbojumbo_client_free(client);
    return 1;
}

static int test_generate_queries_without_sending(void) {
    uint8_t pubkey[32];
    memset(pubkey, 0xaa, 32);

    MumbojumboClient *client = mumbojumbo_client_new(pubkey, ".asd.qwe", MAX_FRAG_DATA_LEN);
    ASSERT(client != NULL, "client creation should succeed");

    char **queries;
    size_t count;

    ASSERT(mumbojumbo_generate_queries(client, (const uint8_t *)"test", 4, &queries, &count) == 0,
           "query generation should succeed");
    ASSERT(count == 1, "should have 1 query");
    ASSERT(strstr(queries[0], ".asd.qwe") != NULL, "query should contain domain");

    free_queries(queries, count);
    mumbojumbo_client_free(client);
    return 1;
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    int total = 0, passed = 0, failed = 0;

    printf("\n=== Mumbojumbo C Client Tests ===\n\n");

    // Key Parsing Tests
    printf("Key Parsing Tests:\n");
    RUN_TEST(test_parse_valid_hex_key);
    RUN_TEST(test_reject_key_without_prefix);
    RUN_TEST(test_reject_key_with_wrong_length);

    // Base32 Encoding Tests
    printf("\nBase32 Encoding Tests:\n");
    RUN_TEST(test_base32_encode_basic);
    RUN_TEST(test_base32_encode_empty);
    RUN_TEST(test_base32_encode_lowercase);
    RUN_TEST(test_base32_encode_no_padding);

    // DNS Label Splitting Tests
    printf("\nDNS Label Splitting Tests:\n");
    RUN_TEST(test_split_to_labels_short);
    RUN_TEST(test_split_to_labels_exact_63);
    RUN_TEST(test_split_to_labels_long);
    RUN_TEST(test_split_to_labels_empty);

    // Fragment Creation Tests
    printf("\nFragment Creation Tests:\n");
    RUN_TEST(test_create_basic_fragment);
    RUN_TEST(test_create_empty_fragment);
    RUN_TEST(test_reject_oversized_fragment);
    RUN_TEST(test_reject_invalid_frag_index);

    // Data Fragmentation Tests
    printf("\nData Fragmentation Tests:\n");
    RUN_TEST(test_fragment_small_data);
    RUN_TEST(test_fragment_exact_max_size);
    RUN_TEST(test_fragment_overflow);
    RUN_TEST(test_fragment_empty_data);

    // Client API Tests
    printf("\nClient API Tests:\n");
    RUN_TEST(test_initialize_client);
    RUN_TEST(test_auto_prepend_dot_to_domain);
    RUN_TEST(test_generate_queries_without_sending);

    printf("\n=== Test Results ===\n");
    printf("Total:  %d\n", total);
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n\n", failed);

    return failed > 0 ? 1 : 0;
}
