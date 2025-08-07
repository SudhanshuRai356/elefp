#include "crypto/AesGcm.hpp"
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
using namespace std;
namespace crypto {
    pair<vector<uint8_t>,vector<uint8_t>> AesGcm::encrypt(const vector<uint8_t>& plaintext, const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& aad) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(!ctx){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the cipher context was not made");
        }
        if(EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL) !=1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the cipher could not be initialized");
        }
        if(EVP_EncryptInit_ex(ctx,NULL,NULL,key.data(),nonce.data()) != 1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("unfortunately the key and nonce were not set for aes-gcm");
        }
        int len;
        if(!aad.empty()){
            if(EVP_EncryptUpdate(ctx,NULL,&len,aad.data(),aad.size()) != 1){
                EVP_CIPHER_CTX_free(ctx);
                throw runtime_error("the aad was not set properly for the aes-gcm");
            }
        }
        vector<uint8_t> ct(plaintext.size());
        if(EVP_EncryptUpdate(ctx,ct.data(),&len,plaintext.data(),plaintext.size()) != 1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the plaintext was not encrypted");
        }
        int ct_len = len;
        if(EVP_EncryptFinal_ex(ctx,ct.data()+len,&len)!=1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("finalisation of encryption failed");
        }
        ct_len += len;
        ct.resize(ct_len);
        vector<uint8_t> auth_tag(16); // aes-gcm normally has a 16 byte auth tag
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag.data()) != 1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the auth tag could not be found");
        }
        EVP_CIPHER_CTX_free(ctx);
        return {ct, auth_tag}; // returns the ciphertext and auth tag as a pair but if decryption fails, it will throw an exception as we have enough error handling
    }
    vector<uint8_t> AesGcm::decrypt(const vector<uint8_t>& ciphertext, const vector<uint8_t>& authtag, const vector<uint8_t>& key, const vector<uint8_t>& nonce, const vector<uint8_t>& aad) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(!ctx){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the cipher context was not made");
        }
        if(EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL) !=1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the cipher decrypt could not be initialized");
        }
        if(EVP_DecryptInit_ex(ctx,NULL,NULL,key.data(),nonce.data()) != 1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("unfortunately the key and nonce were not set for aes-gcm decryption");
        }
        int len=0;
        if(!aad.empty()){
            if(EVP_DecryptUpdate(ctx,NULL,&len,aad.data(),aad.size()) != 1){
                EVP_CIPHER_CTX_free(ctx);
                throw runtime_error("the aad was not set properly for the aes-gcm decryption");
            }
        }
        vector<uint8_t> pt(ciphertext.size());
        if(EVP_DecryptUpdate(ctx,pt.data(),&len,ciphertext.data(), ciphertext.size()) != 1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the ciphertext was not decrypted");
        }
        int pt_len = len;
        if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(authtag.data())) != 1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("the auth tag could not be set for decryption");
        }
        if(EVP_DecryptFinal_ex(ctx,pt.data()+len,&len) != 1){
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("finalisation of decryption failed");
        }
        pt_len += len;
        pt.resize(pt_len);
        EVP_CIPHER_CTX_free(ctx);
        return pt; // will only return the plaintext if decryption is a success, else we have enough error handling which throws an exception
    }
}