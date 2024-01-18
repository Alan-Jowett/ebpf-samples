// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

#include "bpf.h"

// Test for key and value typedefs with CV qualifiers.
// Note: Verifier does not support volatile keys or const values.
typedef volatile uint32_t key_t;
typedef const uint32_t value_t;

typedef struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, key_t);
    __type(value, value_t);
    __uint(max_entries, 1);
} map_t;

__attribute__((section(".maps"), used))
map_t map;

int func(void* ctx) {
    uint32_t key = 0;
    uint32_t* value = bpf_map_lookup_elem(&map, &key);
    if (!value) {
        return 1;
    }
    return 0;
}
