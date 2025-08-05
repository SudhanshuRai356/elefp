#pragma once
#include <vector>
#include <cstdint> // for std::uint8_t
#include <utility> // for std::pair
using namespace std;
namespace crypto{
    class AesGcm{
        public:
        pair<vector<uint8_t>,vector<uint8_t>> encrypt(const vector<uint8_t>& plaintext, const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& aad);
        //encrypts the plaintext via AES-GCM using the parameters needed by AES-GCM and return the ciphertext and auth tag
        vector<uint8_t> decrypt(const vector<uint8_t>& ciphertext, const vector<uint8_t> &authtag, const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& aad);
        //decrypts the ciphertext when all the required params are provided and gives the plaintext if it is not decrypted due to some issue it thorws appropiate errors
    };
}