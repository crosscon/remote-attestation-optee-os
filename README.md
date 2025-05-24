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

Configuring this branch differs a lot from the `crosscon` branch of this repository. Due to issues with reading the CROSSCON Hypervisor configuration, this temporary solution is introduced.

To configure the shared memory with other VMs, the file `core/pta/memread.c` must be modified. At the top, there is the `struct vm_mem_mapping_config config` struct, which contains how the individual VMs are mapped to the OP-TEE OS VM.

Each `mapping` has two attributes: `phy` and `size`. `phy` is the *virtual* address as mapped in the hypervisor config, which appears to be *physical* to OP-TEE (and is mapped to a OP-TEE virtual address internally). `size` specifies how big the shared memory region is.

Creating this configuration from the hypervisor `config.c` file may be automated in the future.

### Build

Building this version of the OP-TEE OS is similar to the `CROSSCON` project this repo is forked from. Instructions for the Raspberry Pi 4 can be found [here](https://github.com/crosscon/CROSSCON-Hypervisor-and-TEE-Isolation-Demos/tree/master/rpi4-ws#step-1-op-tee-os).

