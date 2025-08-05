#include "crypto/HKDF.hpp"
#include <stdexcept>
using namespace std;
namespace crypto {
    vector<uint8_t>HKDF::derive(const vector<uint8_t>& ikm, const vector<uint8_t>& salt, const vector<uint8_t>& info, size_t op_len) {
        throw std::runtime_error("will implement this later");
    }
}