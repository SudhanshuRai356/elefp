#pragma once
#include <vector>
#include <utility> // for std::pair
#include <cstdint> // for std::uint8_t
using namespace std;
namespace crypto {
    class KeyExchange {
        public:
        static pair<vector<uint8_t>,vector<uint8_t>> generate_keypair(); //gen keypair for kyber 512 and will return public key(pk) and secret key(sk)
        static pair<vector<uint8_t>,vector<uint8_t>> encapsulate(const vector<uint8_t>& pk); // encap using the public key and return the ciphertext (ct) and the shared secret (ss)
        static vector<uint8_t> decapsulate(const vector<uint8_t>& ct, const vector<uint8_t> &sk); //decap does what decryption in old encryption algos would do and it takes the ct and the sk and return the recovered ss

        // Dilithium2 post-quantum signature functions for handshake authentication
        static pair<vector<uint8_t>,vector<uint8_t>> generate_dilithium_keypair(); //gen keypair for dilithium2 signatures
        static vector<uint8_t> sign_handshake_transcript(const vector<uint8_t>& secret_key, const vector<uint8_t>& handshake_data); //sign handshake data with dilithium sk
        static bool verify_handshake_signature(const vector<uint8_t>& public_key, const vector<uint8_t>& signature, const vector<uint8_t>& handshake_data); //verify signature with dilithium pk
    };
}