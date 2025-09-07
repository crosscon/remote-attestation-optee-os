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
            .phy = 0x20000000,
            .size = 0x40000000
        },
        [1] = {
            .phy = 0x9200000,
            .size = 0x200000
        }
    }
};

struct crypto_hash_ctx;


TEE_Result get_block_start_addr(
    uint8_t vm_idx,
    uint32_t block_idx,
    paddr_t* start_addr
);

TEE_Result map_vm_mem(
    uint8_t vm_idx,
    uint32_t block_idx,
    void** mem_ptr
);

TEE_Result unmap_vm_mem(
    void* mem_ptr
);

TEE_Result determine_pattern_ending_block_offset_recursively(
    uint8_t vm_idx,
    uint32_t block_idx,
    const char* pattern,
    size_t pattern_size,
    size_t pattern_offset,
    size_t* found_block_idx,
    size_t* found_block_offset,
    bool early_cancel
);

TEE_Result determine_pattern_ending_block_offset(
    uint8_t vm_idx,
    uint32_t block_idx,
    const char* pattern,
    size_t pattern_size,
    size_t* found_block_idx,
    size_t* found_block_offset
);

TEE_Result build_attestation_evidence(
    uint8_t vm_idx,
    uint32_t block_idx,
    size_t block_offset,
    size_t memory_under_test_size,
    struct crypto_hash_ctx* hash_ctx
);

TEE_Result work_on_memory(
    uint8_t vm_idx,
    uint32_t block_idx,
    const char* pattern,
    size_t pattern_size,
    size_t memory_under_test_size,
    uint8_t* output_buffer,
    size_t output_buffer_size
);


TEE_Result get_number_of_blocks(uint8_t vm_idx, size_t* num_blocks) {
    if (vm_idx >= config.mappings_num)
        return TEE_ERROR_ITEM_NOT_FOUND;

    *num_blocks = config.mappings[vm_idx].size / PTA_MEMREAD_MEM_BLOCK_SIZE;
    return TEE_SUCCESS;
}

TEE_Result get_block_start_addr(uint8_t vm_idx, uint32_t block_idx, paddr_t* start_addr) {
    size_t num_blocks;
    struct vm_mem_mapping vm;

    if (vm_idx >= config.mappings_num)
        return TEE_ERROR_ITEM_NOT_FOUND;

    vm = config.mappings[vm_idx];
    if (get_number_of_blocks(vm_idx, &num_blocks) != TEE_SUCCESS || block_idx >= num_blocks)
        return TEE_ERROR_ITEM_NOT_FOUND;

    *start_addr = vm.phy + block_idx * PTA_MEMREAD_MEM_BLOCK_SIZE;
    return TEE_SUCCESS;
}

TEE_Result map_vm_mem(uint8_t vm_idx, uint32_t block_idx, void** mem_ptr) {
    paddr_t block_start_addr;
    void* ptr;
    TEE_Result res;

    res = get_block_start_addr(vm_idx, block_idx, &block_start_addr);
    if (res != TEE_SUCCESS)
        return res;

    ptr = core_mmu_add_mapping(MEM_AREA_IO_NSEC, block_start_addr, PTA_MEMREAD_MEM_BLOCK_SIZE);

    if (ptr == NULL)
        ptr = phys_to_virt(MEM_AREA_IO_NSEC, block_start_addr, PTA_MEMREAD_MEM_BLOCK_SIZE);

    if (ptr == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    *mem_ptr = ptr;

    DMSG("Mapped memory %i:%u\n", vm_idx, block_idx);

    return TEE_SUCCESS;
}

TEE_Result unmap_vm_mem(void* mem_ptr) {
    DMSG("Unmapp(ing) memory\n");
    return core_mmu_remove_mapping(MEM_AREA_IO_NSEC, mem_ptr, PTA_MEMREAD_MEM_BLOCK_SIZE);
}

TEE_Result determine_pattern_ending_block_offset(
    uint8_t vm_idx, uint32_t block_idx,
    const char* pattern, size_t pattern_size,
    size_t* found_block_idx, size_t* found_block_offset
) {
    return determine_pattern_ending_block_offset_recursively(
        vm_idx, block_idx,
        pattern, pattern_size, 0,
        found_block_idx, found_block_offset,
        false
    );
}

TEE_Result determine_pattern_ending_block_offset_recursively(
    uint8_t vm_idx, uint32_t block_idx,
    const char* pattern, size_t pattern_size, size_t pattern_offset,
    size_t* found_block_idx, size_t* found_block_offset,
    bool early_cancel
) {
    TEE_Result res;
    void* mem_ptr;
    const char* block;
    size_t offset_within_block;
    bool pattern_found;
    size_t number_of_blocks;

    res = map_vm_mem(vm_idx, block_idx, &mem_ptr);
    if (res != TEE_SUCCESS)
        return res;

    DMSG("[memread] Recursively searching block %u\n", block_idx);

    block = (const char*) mem_ptr;

    pattern_found = false;
    for (offset_within_block = 0; offset_within_block < PTA_MEMREAD_MEM_BLOCK_SIZE; offset_within_block++) {
        if (block[offset_within_block] == pattern[pattern_offset])
            pattern_offset++;
        else {
            pattern_offset = 0;
            if (early_cancel)
                break;
        }

        if (pattern_offset == pattern_size) {
            pattern_found = true;
            break;
        }
    }

    res = unmap_vm_mem(mem_ptr);
    if (res != TEE_SUCCESS)
        return res;

    if (pattern_found) {
        *found_block_idx = block_idx;
        *found_block_offset = offset_within_block;
        return TEE_SUCCESS;
    }

    if (!pattern_found && pattern_offset > 0) {
        return determine_pattern_ending_block_offset_recursively(
            vm_idx, block_idx + 1,
            pattern, pattern_size,
            pattern_offset,
            found_block_idx,
            found_block_offset,
            true
        );
    }

    if (get_number_of_blocks(vm_idx, &number_of_blocks) != TEE_SUCCESS || block_idx >= number_of_blocks - 1) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    return TEE_ERROR_BUSY;
}

TEE_Result build_attestation_evidence(
    uint8_t vm_idx, uint32_t block_idx, size_t block_offset,
    size_t memory_under_test_size,
    struct crypto_hash_ctx* hash_ctx
) {
    TEE_Result res;
    size_t remaining;
    size_t this_block_to_hash;
    void* mem_ptr;

    remaining = memory_under_test_size;
    while (remaining > 0) {
        res = map_vm_mem(vm_idx, block_idx, &mem_ptr);
        if (res != TEE_SUCCESS)
            return res;

        this_block_to_hash = remaining >= PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset
            ? PTA_MEMREAD_MEM_BLOCK_SIZE - block_offset
            : remaining;

        DMSG("Hashing %lu bytes starting at %u:%lu:%lu\n", this_block_to_hash, vm_idx, block_idx, block_offset);

        res = crypto_hash_update(hash_ctx, ((const uint8_t*) mem_ptr) + block_offset, this_block_to_hash);
        if (res != TEE_SUCCESS) {
            IMSG("Error creating proof: %x\n", res);
            unmap_vm_mem(mem_ptr);
            return res;
        }

        remaining -= this_block_to_hash;
        block_offset = 0;
    }

    return TEE_SUCCESS;
}


TEE_Result work_on_memory(
    uint8_t vm_idx, uint32_t block_idx,
    const char* pattern, size_t pattern_size,
    size_t memory_under_test_size,
    uint8_t* output_buffer, size_t output_buffer_size
) {
    TEE_Result res;

    size_t found_block_idx;
    size_t found_block_offset;

    struct crypto_hash_ctx* ctx;

    res = determine_pattern_ending_block_offset(
        vm_idx, block_idx,
        pattern, pattern_size,
        &found_block_idx, &found_block_offset
    );
    if (res != TEE_SUCCESS)
        return res;

    found_block_idx += (found_block_offset + 1) / PTA_MEMREAD_MEM_BLOCK_SIZE;
    found_block_offset = (found_block_offset + 1) % PTA_MEMREAD_MEM_BLOCK_SIZE;

    DMSG("Found pattern: %u:%lu:%lu\n", vm_idx, found_block_idx, found_block_offset);

    ctx = NULL;
    res = crypto_hash_alloc_ctx((void**) &ctx, TEE_ALG_SHA512);
    if (res != TEE_SUCCESS)
        return res;

    res = crypto_hash_init(ctx);
    if (res != TEE_SUCCESS)
        goto out;

    res = crypto_hash_update(ctx, (const uint8_t*) pattern, pattern_size);
    if (res != TEE_SUCCESS)
        goto out;

    res = build_attestation_evidence(
        vm_idx, found_block_idx,
        found_block_offset,
        memory_under_test_size - pattern_size,
        ctx
    );
    if (res != TEE_SUCCESS) {
        DMSG("Error building attestation evidence (?): %lu\n", res);
        goto out;
    }

    res = crypto_hash_final(ctx, output_buffer, output_buffer_size);
    if (res != TEE_SUCCESS)
        DMSG("Error finalizing hash (?): %lu\n", res);
out:
    crypto_hash_free_ctx(ctx);
    return res;
}


static TEE_Result invoke_command(
    void* sess_ctx __maybe_unused,
    uint32_t cmd_id __maybe_unused,
    uint32_t param_types,
    TEE_Param params[TEE_NUM_PARAMS]
) {
    uint8_t vm_index;
    uint32_t block_index;
    const char* input_pattern;
    size_t input_pattern_size;
    size_t memory_region_under_test_size;
    char* output_buf;
    size_t output_buf_size;

    if (cmd_id != PTA_MEMREAD_CMD_ATTEST_MEMORY)
        return TEE_ERROR_NOT_SUPPORTED;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    vm_index = (uint8_t) params[0].value.a;
    block_index = params[0].value.b;

    input_pattern = (const char*) params[1].memref.buffer;
    input_pattern_size = params[1].memref.size;

    memory_region_under_test_size = params[2].value.a;

    output_buf = (char*) params[3].memref.buffer;
    output_buf_size = params[3].memref.size;

    if (vm_index >= config.mappings_num)
        return TEE_ERROR_BAD_PARAMETERS;

    DMSG("[memread] Block: %u\n", block_index);
    DMSG("[memread] Pattern: ");
    for (size_t i = 0; i < input_pattern_size; i++)
        DMSG("0x%02x ", (unsigned char) input_pattern[i]);;
    DMSG("\n");

    return work_on_memory(
        vm_index, block_index,
        input_pattern, input_pattern_size,
        memory_region_under_test_size,
        output_buf, output_buf_size
    );
}


pseudo_ta_register(
    .uuid = PTA_MEMREAD_UUID,
    .name = PTA_NAME,
    .flags = PTA_DEFAULT_FLAGS,
    .invoke_command_entry_point = invoke_command
);
