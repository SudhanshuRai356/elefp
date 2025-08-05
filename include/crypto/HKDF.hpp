#pragma once
#include <vector>
#include <cstdint> // for std::uint8_t
using namespace std;
namespace crypto{
    class HKDF{
        public:
        static vector<uint8_t> derive(const vector<uint8_t>& ikm, const vector<uint8_t>& salt, const vector<uint8_t>& info, size_t op_len);
        // input key material (ikm) is the key, the salt is a non-secret random value, and info is optional context and op_len is the length of the output, this function is used to expand the ss into more crypto keys
    };
}