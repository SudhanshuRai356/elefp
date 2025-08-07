#include "crypto/HKDF.hpp"
#include <stdexcept>
#include<openssl/hmac.h>
#include<openssl/evp.h>
#include<vector>
using namespace std;
namespace crypto {
    // the whole method of HKDF is that it takes the input key material (ikm) and some salt and then finds some derivable keying material (prk) using HMAC and then that prk is used to derive output keying material (okm) using HMAC again to add more controlled entropy
    vector<uint8_t>HKDF::derive(const vector<uint8_t>& ikm, const vector<uint8_t>& salt, const vector<uint8_t>& info, size_t op_len) {
        const EVP_MD *hash = EVP_sha256();
        size_t hash_len = EVP_MD_size(hash);
        vector<uint8_t>act_salt;
        if(salt.empty()){ // if given salt is empty, we use a zero salt 
            act_salt=vector<uint8_t>(hash_len,0x00);
        }
        else{
            act_salt=salt;
        }
        vector<uint8_t>prk(hash_len);
        unsigned int prk_len=0;
        if(!HMAC(hash,act_salt.data(),act_salt.size(),ikm.data(),ikm.size(),prk.data(),&prk_len)){ //prk is found using HMAC with the ikm and salt
            throw runtime_error("HMAC failed to find PRK");
        }
        if(op_len > 255 * hash_len) {
            throw runtime_error("Output length is more than max allowed");
        }
        vector<uint8_t>okm;
        okm.reserve(op_len);
        vector<uint8_t>prev;
        for(uint8_t counter=1;okm.size() < op_len; ++counter) { //we use counter to keep track of how many times the keying material has been derived
            vector<uint8_t>data(prev);
            data.insert(data.end(), info.begin(), info.end());
            data.push_back(counter);
            vector<uint8_t>block(hash_len);
            unsigned int len = 0;
            if(!HMAC(hash,prk.data(),prk_len,data.data(),data.size(),block.data(),&len)) { // HMAC is used to continously derive the keying material till we get the final okm
                throw runtime_error("HMAC failed to get the OKM");
            }
            size_t to_copy = min(static_cast<size_t>(len),op_len-okm.size());
            okm.insert(okm.end(), block.begin(), block.begin() + to_copy);
            prev = block;
        }
        return okm;    
    }
}