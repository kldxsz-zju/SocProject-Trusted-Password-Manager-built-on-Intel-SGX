## brief&hardware requests
Our proposed project is a secure password vault based on Intel SGX Sealing.

The main idea is to keep plaintext passwords and sensitive keys inside an SGX Enclave, and use Sealing to store the password vault securely on disk. We plan to test normal recovery after restart, file tampering, copying sealed files, software upgrades, and rollback attacks.

We would also like to compare the MRENCLAVE and MRSIGNER sealing policies, especially their differences in security and software upgradability.

To complete the hardware-based experiments, we would like to ask whether there is a machine available that supports Intel SGX Hardware Mode. Ideally, the machine should have SGX enabled in the BIOS and have the SGX driver and Intel SGX SDK installed.

We only need access to one SGX-capable machine for the final validation and demonstration. We can do most of the early development in Simulation Mode on our own computers.
