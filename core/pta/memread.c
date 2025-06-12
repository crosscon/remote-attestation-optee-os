#include "compiler.h"
#include "tee_api_defines.h"
#include <string.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <pta_memread.h>

#include <crypto/crypto.h>
#include <tee_api_types.h>

//#include <config.h>

#define PTA_NAME "memread.pta"

#define PTA_MEMREAD_MEM_BLOCK_SIZE 0x200000


struct vm_mem_mapping {
    size_t phy;
    size_t size;
};

struct vm_mem_mapping_config {
    size_t mappings_num;
    struct vm_mem_mapping* mappings;
};

struct vm_mem_mapping_config config = {
    .mappings_num = 2,
    .mappings = (struct vm_mem_mapping[]){
        [0] = {
            .phy = 0x9000000,
            .size = 0x2000000
        },
        [1] = {
            .phy = 0x9200000,
            .size = 0x200000
        }
    }
};


TEE_Result get_pattern_base_address_in_memory_region(
    size_t memory_start,
    size_t memory_size,
    const char* pattern,
    size_t pattern_size,
    size_t test_size,
    char** memory_to_hash
);


TEE_Result get_pattern_base_address_in_memory_region(size_t memory_start, size_t memory_size, const char* pattern, size_t pattern_size, size_t test_size, char** memory_to_hash) {
    for (size_t i = memory_start; i < memory_start + memory_size - pattern_size - test_size + 1; i++) {
        char* offset = (char*) i;
        if (memcmp(offset, pattern, pattern_size) == 0) {
            *memory_to_hash = offset;
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_ITEM_NOT_FOUND;
}


TEE_Result work_on_memory_block(size_t start_memory_address, const char* memory_pattern, size_t memory_pattern_size, size_t area_to_hash_total_size, bool* pattern_found, void* hash_ctx, size_t* memory_offset) {
    TEE_Result res;
    TEE_Result res_mem;
    void* virtual_start_addr;
    size_t block_offset;

    virtual_start_addr = core_mmu_add_mapping(MEM_AREA_IO_NSEC, start_memory_address, PTA_MEMREAD_MEM_BLOCK_SIZE);

    if (virtual_start_addr == NULL)
        virtual_start_addr = phys_to_virt(MEM_AREA_IO_NSEC, start_memory_address, PTA_MEMREAD_MEM_BLOCK_SIZE);

    if (virtual_start_addr == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = TEE_SUCCESS;

    char* block = (char*) virtual_start_addr;
    block_offset = 0;

    if (!(*pattern_found)) { // pattern not found, looking for matches in memory
        for (block_offset = 0; block_offset < PTA_MEMREAD_MEM_BLOCK_SIZE; block_offset++) {
            if (block[block_offset] == memory_pattern[*memory_offset]) {
                (*memory_offset)++;

                if (*memory_offset >= memory_pattern_size) {
                    *pattern_found = true;
                    block_offset++;
                    break;
                }
            } else {
                *memory_offset = 0;
            }
        }
    }

    if (*pattern_found && area_to_hash_total_size - *memory_offset > 0 && PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset > 0) { // pattern was found, hash the entire or remaining part of the block
        size_t bytes_to_hash =
            (area_to_hash_total_size - *memory_offset) >= (PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset)
                ? PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset
                : area_to_hash_total_size - *memory_offset;

        res = crypto_hash_update(hash_ctx, (const uint8_t*) block + block_offset, bytes_to_hash);
        *memory_offset += bytes_to_hash;
    }

    res_mem = core_mmu_remove_mapping(MEM_AREA_IO_NSEC, virtual_start_addr, PTA_MEMREAD_MEM_BLOCK_SIZE);
    if (res == TEE_SUCCESS)
        return res_mem;
    return res;
}


static TEE_Result invoke_command(
    void* sess_ctx __maybe_unused,
    uint32_t cmd_id __maybe_unused,
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS]
) {
    TEE_Result res;

    uint8_t vm_index;
    const char* input_pattern;
    size_t input_pattern_size;
    size_t memory_region_under_test_size;
    char* output_buf;
    size_t output_buf_size;

    struct vm_mem_mapping map;
    struct crypto_hash_ctx* ctx;
    bool pattern_found;
    size_t memory_offset;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    vm_index = (uint8_t) params[0].value.a;

    input_pattern = (const char*) params[1].memref.buffer;
    input_pattern_size = params[1].memref.size;

    memory_region_under_test_size = params[2].value.a;

    output_buf = (char*) params[3].memref.buffer;
    output_buf_size = params[3].memref.size;

    if (vm_index >= config.mappings_num)
        return TEE_ERROR_BAD_PARAMETERS;
    map = config.mappings[vm_index];

    ctx = NULL;
    res = crypto_hash_alloc_ctx((void**) &ctx, TEE_ALG_SHA512);
    if (res != TEE_SUCCESS)
        return res;

    res = crypto_hash_init(ctx);
    if (res != TEE_SUCCESS)
        goto out;

    res = crypto_hash_update(ctx, (const uint8_t*) input_pattern, input_pattern_size);
    if (res != TEE_SUCCESS)
        goto out;

    pattern_found = false;
    memory_offset = 0;
    for (size_t block_offset = 0; block_offset < map.size / PTA_MEMREAD_MEM_BLOCK_SIZE; block_offset++) {
        res = work_on_memory_block(
            map.phy + block_offset * PTA_MEMREAD_MEM_BLOCK_SIZE,
            input_pattern, input_pattern_size,
            memory_region_under_test_size,
            &pattern_found,
            ctx,
            &memory_offset
        );

        if (memory_offset >= memory_region_under_test_size)
            break;
    }

    res = crypto_hash_final(ctx, (uint8_t*) output_buf, output_buf_size);

out:
    crypto_hash_free_ctx(ctx);
    return res;
}


pseudo_ta_register(
    .uuid = PTA_MEMREAD_UUID,
    .name = PTA_NAME,
    .flags = PTA_DEFAULT_FLAGS,
    .invoke_command_entry_point = invoke_command
);
