#include "compiler.h"
#include "tee_api_defines.h"
#include <string.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <pta_memread.h>

#include <crypto/crypto.h>
#include <tee_api_types.h>

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


TEE_Result work_on_memory_block(
    size_t start_memory_address,                // where the physical memory region starts on the Pi
    const char* memory_pattern,                 // pattern to look for
    size_t memory_pattern_size,                 // len(^)
    size_t area_to_hash_total_size,             // number of bytes to hash (incl. pattern)
    bool* pattern_found,                        // was pattern found so far?
    void* hash_ctx,                             // hash context to update
    size_t* bytes_in_target_region_processed    // number of bytes in the target memory region worked on so far (no. of bytes matched in pattern/hashed in provided ctx)
);


TEE_Result work_on_memory_block(size_t start_memory_address, const char* memory_pattern, size_t memory_pattern_size, size_t area_to_hash_total_size, bool* pattern_found, void* hash_ctx, size_t* bytes_in_target_region_processed) {
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

    if (!(*pattern_found)) { // pattern not found in previous blocks, looking for matches in memory
        DMSG("[memread] Pattern not found in previous block(s), searching now\n");
        for (block_offset = 0; block_offset < PTA_MEMREAD_MEM_BLOCK_SIZE; block_offset++) {
            if (block[block_offset] == memory_pattern[*bytes_in_target_region_processed]) {
                (*bytes_in_target_region_processed)++;
                
                if (*bytes_in_target_region_processed > 4)
                    DMSG("[memread] Bytes matched so far: %d (address offset within block: %x)\n", *bytes_in_target_region_processed, block_offset);

                if (*bytes_in_target_region_processed >= memory_pattern_size) {
                    *pattern_found = true;
                    block_offset++;
                    DMSG("[memread] Pattern found in memory, continuing with hashing\n");
                    break;
                }
            } else {
                *bytes_in_target_region_processed = 0;
            }
        }
    } else {
        DMSG("[memread] Pattern found in previous block(s), continuing hashing procedure\n");
    }

    if (*pattern_found && area_to_hash_total_size - *bytes_in_target_region_processed > 0 && PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset > 0) { // pattern was found, hash the entire or remaining part of the block
        size_t bytes_to_hash =
            (area_to_hash_total_size - *bytes_in_target_region_processed) >= (PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset)
                ? PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset
                : area_to_hash_total_size - *bytes_in_target_region_processed;

        DMSG("[memread] Hashing %x bytes of memory in this block (starting at %x)\n", bytes_to_hash, block_offset);

        res = crypto_hash_update(hash_ctx, (const uint8_t*) block + block_offset, bytes_to_hash);
        *bytes_in_target_region_processed += bytes_to_hash;
    }

    DMSG("[memread] Finished block");

    res_mem = core_mmu_remove_mapping(MEM_AREA_IO_NSEC, virtual_start_addr, PTA_MEMREAD_MEM_BLOCK_SIZE);
    if (res_mem != TEE_SUCCESS)
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
    size_t bytes_in_target_region_processed;

    size_t number_blocks_total;
    size_t block_physical_address;

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

    DMSG("[memread] Pattern: ");
    for (size_t i = 0; i < input_pattern_size; i++)
        DMSG("0x%02x ", (unsigned char) input_pattern[i]);;
    DMSG("\n");

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
    bytes_in_target_region_processed = 0;
    number_blocks_total = map.size / PTA_MEMREAD_MEM_BLOCK_SIZE;

    IMSG("[memread] Scanning memory for pattern & hashing it\n");
    for (size_t block_offset = 0; block_offset < number_blocks_total; block_offset++) {
        block_physical_address = map.phy + block_offset * PTA_MEMREAD_MEM_BLOCK_SIZE;
        DMSG("[memread] Starting work on block %d/%d (start address: %x)\n", block_offset, number_blocks_total, block_physical_address);
        res = work_on_memory_block(
            block_physical_address,
            input_pattern, input_pattern_size,
            memory_region_under_test_size,
            &pattern_found,
            ctx,
            &bytes_in_target_region_processed
        );

        if (bytes_in_target_region_processed >= memory_region_under_test_size)
            break;
    }

    if (!pattern_found) {
        IMSG("[memread] No pattern found!\n");
        res = TEE_ERROR_ITEM_NOT_FOUND;
        goto out;
    }

    res = crypto_hash_final(ctx, (uint8_t*) output_buf, output_buf_size);

    IMSG("[memread] Hash finalized\n");
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
