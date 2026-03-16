#include "crypto/KeyExchange.hpp"
#include <stdexcept>
#include<oqs/oqs.h>
using namespace std;
namespace crypto {
    pair<vector<uint8_t>,vector<uint8_t>> KeyExchange::generate_keypair(){
        OQS_KEM *kem=OQS_KEM_new(OQS_KEM_alg_kyber_512); // making the kyber kem object
        if(kem==nullptr){
            throw runtime_error("kem creation failed");
        }
        vector<uint8_t> sk(kem->length_secret_key),pk(kem->length_public_key); //initialised the secret and public key as those are the keypairs generated
        if(OQS_KEM_keypair(kem,pk.data(),sk.data())!=OQS_SUCCESS){ // making the keypair and if its not made then throwing error
            OQS_KEM_free(kem);
            throw runtime_error("Keypair gen failed");
        }
        OQS_KEM_free(kem);
        return {pk,sk};
    }
    pair<vector<uint8_t>,vector<uint8_t>> KeyExchange::encapsulate(const vector<uint8_t>& pk){
        OQS_KEM *kem=OQS_KEM_new(OQS_KEM_alg_kyber_512);
        if(kem==nullptr){
            throw runtime_error("kem creation failed");
        }
        vector<uint8_t> ct(kem->length_ciphertext),ss(kem->length_shared_secret);
        if(OQS_KEM_encaps(kem,ct.data(),ss.data(),pk.data())!=OQS_SUCCESS){ // initialized and got the ss and ct using the pk
            OQS_KEM_free(kem);
            throw runtime_error("encaps failed");
        }
        OQS_KEM_free(kem);
        return {ct,ss};
    }
    vector<uint8_t> KeyExchange::decapsulate(const vector<uint8_t>& ct, const vector<uint8_t> &sk){
        OQS_KEM *kem=OQS_KEM_new(OQS_KEM_alg_kyber_512);
        if(kem==nullptr){
            throw runtime_error("kem creation failed");
        }
        vector<uint8_t>ss_dec(kem->length_shared_secret);
        if(OQS_KEM_decaps(kem,ss_dec.data(),ct.data(),sk.data())!=OQS_SUCCESS){ // used decap and got the ss using the sk and ct hints
            OQS_KEM_free(kem);
            throw runtime_error("decaps failed");
        }
        OQS_KEM_free(kem);
        return ss_dec;
    }
    pair<vector<uint8_t>,vector<uint8_t>> KeyExchange::generate_dilithium_keypair(){
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if(sig==nullptr){
            throw runtime_error("Dilithium sig object creation failed");
        }
        vector<uint8_t> public_key(sig->length_public_key);
        vector<uint8_t> secret_key(sig->length_secret_key);
        if(OQS_SIG_keypair(sig, public_key.data(), secret_key.data())!=OQS_SUCCESS){
            OQS_SIG_free(sig);
            throw runtime_error("Dilithium keypair generation failed");
        }
        OQS_SIG_free(sig);
        return {public_key, secret_key};
    }
    vector<uint8_t> KeyExchange::sign_handshake_transcript(
        const vector<uint8_t>& secret_key,
        const vector<uint8_t>& handshake_data
    ){
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if(sig==nullptr){
            throw runtime_error("Dilithium sig object creation failed");
        }
        if(secret_key.size() != sig->length_secret_key){
            OQS_SIG_free(sig);
            throw runtime_error("Invalid Dilithium secret key size");
        }
        vector<uint8_t> signature(sig->length_signature);
        size_t sig_len = 0;
        if(OQS_SIG_sign(sig, signature.data(), &sig_len, handshake_data.data(), handshake_data.size(), secret_key.data()) != OQS_SUCCESS){
            OQS_SIG_free(sig);
            throw runtime_error("Dilithium signing failed");
        }
        signature.resize(sig_len);
        OQS_SIG_free(sig);
        return signature;
    }
    bool KeyExchange::verify_handshake_signature(
        const vector<uint8_t>& public_key,
        const vector<uint8_t>& signature,
        const vector<uint8_t>& handshake_data
    ){
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if(sig==nullptr){
            throw runtime_error("Dilithium sig object creation failed");
        }
        if(public_key.size() != sig->length_public_key){
            OQS_SIG_free(sig);
            throw runtime_error("Invalid Dilithium public key size");
        }
        OQS_STATUS result = OQS_SIG_verify(sig, handshake_data.data(), handshake_data.size(), signature.data(), signature.size(), public_key.data());
        OQS_SIG_free(sig);
        return result == OQS_SUCCESS;
    }
}
