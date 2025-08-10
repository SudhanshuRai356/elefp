#include "transport/TransportUtil.hpp"
#include <iomanip>
#include <sstream>
#include <stdexcept>
namespace transport
{
    namespace util
    {
        array<uint8_t, 12> make_nonce(uint64_t counter)
        {
            array<uint8_t, 12> nonce{};
            nonce[0] = nonce[1] = nonce[2] = nonce[3] = 0; // clearing the first 4 bytes
            for (int i = 0; i < 8; ++i)
            {
                nonce[11 - i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xFF); // adding the next 8 bytes of the nonce using the counter
            }
            return nonce;
        }
        vector<uint8_t> hex_to_bytes(const string hex){ // converting hex string to byte vector
            if(hex.length()%2!=0){
                throw runtime_error("hex input of packet is wrong");
            }
            vector<uint8_t> bytes;
            bytes.reserve(hex.length() / 2);
            for(size_t i = 0; i < hex.length(); i += 2) {
                unsigned int byte =0;
                istringstream iss(hex.substr(i, 2));
                iss >> std::hex>>byte;
                bytes.push_back(static_cast<uint8_t>(byte));
            }
            return bytes;
        }
        string bytes_to_hex(const vector<uint8_t>& bytes) { // converting byte vector to hex string
            ostringstream oss;
            oss << std::hex << std::setfill('0');
            for(auto b:bytes){
                oss << std::setw(2) << static_cast<int>(b);
            }
            return oss.str();
        }
    }
}