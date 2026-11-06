/* Generates src/execution/import/testdata/fixture.mdbx: a small MDBX database written by the
 * real libmdbx (the copy reth vendors, v0.13.12), so needlefish's reader is tested against the
 * library's own output. Not part of the build. Regenerate:
 *   cc -O2 -o /tmp/mdbx_fixture etc/import/mdbx_fixture.c <libmdbx>/mdbx.c -I<libmdbx> -lpthread
 *   /tmp/mdbx_fixture src/execution/import/testdata/fixture.mdbx
 * Contents come from splitmix64; mdbx_reader_test.zig regenerates them in the same order. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mdbx.h"

static uint64_t state = 0x6e666d6478ULL;
static uint64_t next(void) {
  uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}
static void fill(uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i += 8) {
    uint64_t v = next();
    for (size_t j = 0; j < 8 && i + j < n; j++) b[i + j] = (uint8_t)(v >> (8 * j));
  }
}
#define CHECK(x) do { int rc_ = (x); if (rc_ != MDBX_SUCCESS) { \
  fprintf(stderr, "%s:%d %s: %s\n", __FILE__, __LINE__, #x, mdbx_strerror(rc_)); exit(1); } } while (0)

enum { plain_count = 3000, big_count = 20, extra_count = 100 };
static const unsigned dup_counts[] = {1, 2, 7, 40, 3000};
static uint8_t plain_keys[plain_count][32];
static uint8_t buffer[64 << 10];

static void put(MDBX_txn *txn, MDBX_dbi dbi, const uint8_t *k, size_t kl, const uint8_t *v, size_t vl) {
  MDBX_val key = {(void *)k, kl}, val = {(void *)v, vl};
  CHECK(mdbx_put(txn, dbi, &key, &val, MDBX_UPSERT));
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  remove(argv[1]);
  char lck[4096];
  snprintf(lck, sizeof lck, "%s-lck", argv[1]);
  remove(lck);
  MDBX_env *env;
  CHECK(mdbx_env_create(&env));
  CHECK(mdbx_env_set_maxdbs(env, 16));
  CHECK(mdbx_env_set_geometry(env, -1, -1, 64 << 20, 1 << 20, 1 << 20, 4096));
  CHECK(mdbx_env_open(env, argv[1], MDBX_NOSUBDIR | MDBX_SYNC_DURABLE, 0644));
  MDBX_txn *txn;
  MDBX_dbi plain, big, dup, empty;
  CHECK(mdbx_txn_begin(env, NULL, MDBX_TXN_READWRITE, &txn));
  CHECK(mdbx_dbi_open(txn, "Plain", MDBX_CREATE, &plain));
  CHECK(mdbx_dbi_open(txn, "Big", MDBX_CREATE, &big));
  CHECK(mdbx_dbi_open(txn, "Dup", MDBX_CREATE | MDBX_DUPSORT, &dup));
  CHECK(mdbx_dbi_open(txn, "Empty", MDBX_CREATE, &empty));
  for (int i = 0; i < plain_count; i++) {
    fill(plain_keys[i], 32);
    size_t len = next() % 120 + 1;
    fill(buffer, len);
    put(txn, plain, plain_keys[i], 32, buffer, len);
  }
  for (int i = 0; i < big_count; i++) {
    uint8_t key[32];
    fill(key, 32);
    size_t len = 3000 + next() % 37000;
    fill(buffer, len);
    put(txn, big, key, 32, buffer, len);
  }
  uint8_t dup_keys[5][32];
  for (int i = 0; i < 5; i++) {
    fill(dup_keys[i], 32);
    for (unsigned j = 0; j < dup_counts[i]; j++) {
      size_t len = 32 + next() % 33;
      fill(buffer, len);
      put(txn, dup, dup_keys[i], 32, buffer, len);
    }
  }
  CHECK(mdbx_txn_commit(txn));
  /* Churn: deletes and rewrites, so pages are freed and reused across transactions. */
  CHECK(mdbx_txn_begin(env, NULL, MDBX_TXN_READWRITE, &txn));
  for (int i = 0; i < plain_count; i++) {
    MDBX_val key = {plain_keys[i], 32};
    if (i % 7 == 0) {
      CHECK(mdbx_del(txn, plain, &key, NULL));
    } else if (i % 5 == 0) {
      size_t len = next() % 200 + 1;
      fill(buffer, len);
      put(txn, plain, plain_keys[i], 32, buffer, len);
    }
  }
  MDBX_val gone = {dup_keys[1], 32};
  CHECK(mdbx_del(txn, dup, &gone, NULL));
  CHECK(mdbx_txn_commit(txn));
  CHECK(mdbx_txn_begin(env, NULL, MDBX_TXN_READWRITE, &txn));
  for (int i = 0; i < extra_count; i++) {
    uint8_t key[32];
    fill(key, 32);
    size_t len = next() % 120 + 1;
    fill(buffer, len);
    put(txn, plain, key, 32, buffer, len);
  }
  CHECK(mdbx_txn_commit(txn));
  CHECK(mdbx_env_close(env));
  remove(lck);
  return 0;
}
