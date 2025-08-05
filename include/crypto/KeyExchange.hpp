#pragma once
#include <vector>
#include <utility> // for std::pair
#include <cstdint> // for std::uint8_t
using namespace std;
namespace crypto {
    class KeyExchange {
        public:
        pair<vector<uint8_t>,vector<uint8_t>> generate_keypair(); //gen keypair for kyber 512 and will return public key(pk) and secret key(sk)
        pair<vector<uint8_t>,vector<uint8_t>> encapsulate(const vector<uint8_t>& pk); // encap using the public key and return the ciphertext (ct) and the shared secret (ss)
        vector<uint8_t> decapsulate(const vector<uint8_t>& ct, const vector<uint8_t> &sk); //decap does what decryption in old encryption algos would do and it takes the ct and the sk and return the recovered ss
    };
}