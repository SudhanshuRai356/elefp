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

    // Dilithium authentication keys
    vector<uint8_t> dilithium_pk; // our dilithium public key
    vector<uint8_t> dilithium_sk; // our dilithium secret key
    vector<uint8_t> peer_dilithium_pk; // the peer's dilithium public key (set after handshake)
    vector<uint8_t> handshake_transcript; // stored transcript for verifying client sig on server side

public:
    SecureSession();
    // Original (unauthenticated) handshake methods - kept for backward compat
    vector<uint8_t> server_handle_public_key(const vector<uint8_t>& client_pk); // server handles client public key and returns its ciphertext for agreement
    void client_process_server_hello(const vector<uint8_t>& server_ct); //accepts the server's ct and derives the shared secret key
    void set_client_keypair(const vector<uint8_t>&pk,const vector<uint8_t>&sk);

    // Dilithium-authenticated handshake methods
    // Server side: receives client_pk + client_dilithium_pk, returns ct + server_dilithium_pk + signature
    vector<uint8_t> server_handle_public_key_authenticated(const vector<uint8_t>& client_pk, const vector<uint8_t>& client_dili_pk);
    // Client side: processes the server response (ct + server_dilithium_pk + signature), returns client signature for server to verify
    vector<uint8_t> client_process_server_hello_authenticated(const vector<uint8_t>& server_ct, const vector<uint8_t>& server_dili_pk, const vector<uint8_t>& server_signature, const vector<uint8_t>& original_client_pk);
    // Server verifies client's signature to complete mutual auth
    bool server_verify_client_signature(const vector<uint8_t>& client_signature, const vector<uint8_t>& server_ct);

    // Dilithium key management
    void generate_dilithium_keys(); // generates a new dilithium keypair and stores it
    void set_dilithium_keypair(const vector<uint8_t>& pk, const vector<uint8_t>& sk);
    const vector<uint8_t>& get_dilithium_pk() const { return dilithium_pk; }
    const vector<uint8_t>& get_peer_dilithium_pk() const { return peer_dilithium_pk; }

    vector<uint8_t> encrypt_packet(const vector<uint8_t>& packet,const vector<uint8_t>& aad = {}); // encryption
    vector<uint8_t> decrypt_packet(const vector<uint8_t>& packet,const vector<uint8_t>& aad = {}); // decryption
    bool is_authenticated() const; // checks if the session is authenticated
};
}
