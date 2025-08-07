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
        vector<uint8_t>ss_dec(kem->length_shared_secret);
        if(OQS_KEM_decaps(kem,ss_dec.data(),ct.data(),sk.data())!=OQS_SUCCESS){ // used decap and got the ss using the sk and ct hints
            OQS_KEM_free(kem);
            throw runtime_error("decaps failed");
        }
        OQS_KEM_free(kem);
        return ss_dec;
    }
}