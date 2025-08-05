#include "crypto/KeyExchange.hpp"
#include <stdexcept>
using namespace std;
namespace crypto {
    pair<vector<uint8_t>,vector<uint8_t>> KeyExchange::generate_keypair(){
        throw std::runtime_error("will implement this later");
    }
    pair<vector<uint8_t>,vector<uint8_t>> KeyExchange::encapsulate(const vector<uint8_t>& pk){
        throw std::runtime_error("will implement this later");
    }
    vector<uint8_t> KeyExchange::decapsulate(const vector<uint8_t>& ct, const vector<uint8_t> &sk){
        throw std::runtime_error("will implement this later");
    }
}