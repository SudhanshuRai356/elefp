#include "crypto/HKDF.hpp"
#include "crypto/AesGcm.hpp"
#include "crypto/KeyExchange.hpp"
#include <cassert>
#include <vector>
#include <cstdint>

int main() {
    // instantiate KeyExchange,HKDF and AesGcm classes
    crypto::HKDF hkdf;
    crypto::AesGcm aes;
    crypto::KeyExchange ke;

    // generate and test Kyber512 keypair
    auto [pk, sk]= ke.generate_keypair();
    auto [ct, ss1]= ke.encapsulate(pk);
    auto ss2= ke.decapsulate(ct, sk);
    assert(ss1 == ss2);
    // derive 32-byte symmetric key via HKDF-SHA256
    auto key = hkdf.derive(ss1, {}, {}, 32);
    assert(key.size() == 32);
    // AES-GCM encrypt/decrypt round-trip
    std::vector<uint8_t>pt= { 'h','e','l','l','o' };
    std::vector<uint8_t>iv(12, 0);
    std::vector<uint8_t>aad;
    auto [ciphertext, auth_tag]=aes.encrypt(pt, key, iv, aad);
    auto decrypted_pt=aes.decrypt(ciphertext, auth_tag, key, iv, aad);
    assert(decrypted_pt == pt);
    return 0;
}
