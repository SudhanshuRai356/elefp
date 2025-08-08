#pragma once
#include <cstdint>
#include <vector>
using namespace std;
namespace transport {
struct Packet {
    vector<uint8_t> data; // actual data
    vector<uint8_t> aad; // meta data
    vector<uint8_t> auth_tag; // it right there in the name
};
}