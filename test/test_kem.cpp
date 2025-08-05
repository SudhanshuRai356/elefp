#include <iostream>
#include <oqs/oqs.h>
#include <vector>
#include <cstring>
#include <cassert>
using namespace std;
int main(){
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if(!kem){
        cerr<< "kem is null" << endl;
        return 1;
    }
    vector<uint8_t> pk(kem->length_public_key);
    vector<uint8_t> sk(kem->length_secret_key);
    vector<uint8_t> ct(kem->length_ciphertext);
    vector<uint8_t> ss_enc(kem->length_shared_secret);
    vector<uint8_t> ss_dec(kem->length_shared_secret);
    if(OQS_KEM_keypair(kem, pk.data(),sk.data())!=OQS_SUCCESS){
        cerr<< "keypair gen failed" << endl;
        return 1;
    }
    if(OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data())!=OQS_SUCCESS){
        cerr<< "encaps failed" << endl;
        return 1;
    }
    if(OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), sk.data())!=OQS_SUCCESS){
        cerr<< "decaps failed" << endl;
        return 1;
    }
    bool ok = (memcmp(ss_enc.data(), ss_dec.data(), kem->length_shared_secret) == 0);
    if(!ok){
        cerr<< "shared secret mismatch" << endl;
        return 1;
    }
    cout << "Test passed!" << endl;
    OQS_KEM_free(kem);
    return 0;
}