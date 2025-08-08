#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>
using namespace std;
namespace transport {
class SecureSession {
private:
    vector<uint8_t> client_public_key;
    vector<uint8_t> client_secret_key;
    vector<uint8_t> session_key;
    bool authenticated = false;
    uint64_t send_counter = 0;
    uint64_t receive_counter = 0;
    array<uint8_t, 12> make_nonce(uint64_t counter); // takes 64 bit counter and converts to a 12 byte nonce
public:
    SecureSession();
    vector<uint8_t> server_handle_public_key(const vector<uint8_t>& client_pk); // server handles client public key and returns its ciphertext for agreement
    void client_process_server_hello(const vector<uint8_t>& server_ct); //accepts the server's ct and derives the shared secret key
    void set_client_keypair(const vector<uint8_t>&pk,vector<uint8_t>&sk);
    vector<uint8_t> encrypt_packet(const vector<uint8_t>& packet,const vector<uint8_t>& aad = {}); // encryption
    vector<uint8_t> decrypt_packet(const vector<uint8_t>& packet,const vector<uint8_t>& aad = {}); // decryption
    bool is_authenticated() const; // checks if the session is authenticated
};
}
