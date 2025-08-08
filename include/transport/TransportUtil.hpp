#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>
using namespace std;
namespace transport {
    namespace util{
        array<uint8_t, 12> make_nonce(uint64_t counter); // takes 64 bit counter hence uint64_t and converts to a 12 byte nonce
        vector<uint8_t>hex_to_bytes(const string& hex); // basic convert hext to bytes
        string bytes_to_hex(const vector<uint8_t>& bytes);  // basic convert bytes to hex because when encrypted some stuff becomes unprintable and might break the code
    }
}