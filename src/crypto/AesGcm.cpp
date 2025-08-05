#include "crypto/AesGcm.hpp"
#include <stdexcept>
using namespace std;
namespace crypto {
    pair<vector<uint8_t>,vector<uint8_t>> AesGcm::encrypt(const vector<uint8_t>& plaintext, const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& aad) {
        throw std::runtime_error("will implement this later");
    }
    vector<uint8_t> AesGcm::decrypt(const vector<uint8_t>& ciphertext, const vector<uint8_t>& authtag, const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& aad) {
        throw std::runtime_error("will implement this later");
    }
}