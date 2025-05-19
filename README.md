# OP-TEE Trusted OS
This git contains source code for the secure side implementation of OP-TEE
project.

All official OP-TEE documentation has moved to http://optee.readthedocs.io.

// OP-TEE core maintainers


# Modifications for Remote Attestation:
In order to work with the remote attestation TA, this code has been modified from the original by
1. adjusting the `libmbedtls` configuration file to add required functionality (particularly for mTLS)
2. extending the core with a Pseudo TA that permits reading another VM's memory

### Configuration

In order to read another VM's shared memory, this OS must know its own VM index. For this, the `MEMREAD_THIS_VM_ID` value must be set in `core/pta/memread.c`.

### Build

Building this OS differs only slightly from the procedure specified by the [CROSSCON instructions](https://github.com/crosscon/CROSSCON-Hypervisor-and-TEE-Isolation-Demos/) as the Hypervisor Config header file (`CROSSCON-Hypervisor/src/core/inc/config.h`) must be available when compiling as well as the final `config.c` file used for building the hypervisor.
