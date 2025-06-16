#include <oqs/kem.h>
#include <iostream>
#include <cstring>

int main() {
    // Select Kyber512
    const char *alg_name = OQS_KEM_alg_kyber_512;
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        std::cerr << "Kyber512 is not enabled in this build of liboqs.\n";
        return 1;
    }

    // Initialize KEM object
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) {
        std::cerr << "Failed to initialize KEM.\n";
        return 1;
    }

    // Allocate memory
    uint8_t *pk = new uint8_t[kem->length_public_key];
    uint8_t *sk = new uint8_t[kem->length_secret_key];
    uint8_t *ciphertext = new uint8_t[kem->length_ciphertext];
    uint8_t *shared_secret_enc = new uint8_t[kem->length_shared_secret];
    uint8_t *shared_secret_dec = new uint8_t[kem->length_shared_secret];

    // Keygen
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        std::cerr << "Keypair generation failed.\n";
        return 1;
    }

    // Encapsulation
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, pk) != OQS_SUCCESS) {
        std::cerr << "Encapsulation failed.\n";
        return 1;
    }

    // Decapsulation
    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, sk) != OQS_SUCCESS) {
        std::cerr << "Decapsulation failed.\n";
        return 1;
    }

    // Compare shared secrets
    bool match = std::memcmp(shared_secret_enc, shared_secret_dec, kem->length_shared_secret) == 0;
    std::cout << (match ? "✅ Key exchange successful." : "❌ Key mismatch.") << "\n";

    // Cleanup
    delete[] pk;
    delete[] sk;
    delete[] ciphertext;
    delete[] shared_secret_enc;
    delete[] shared_secret_dec;
    OQS_KEM_free(kem);

    return match ? 0 : 1;
}
