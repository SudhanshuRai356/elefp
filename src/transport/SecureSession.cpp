#include "transport/SecureSession.hpp"
#include "transport/TransportUtil.hpp"
#include <crypto/KeyExchange.hpp>
#include <crypto/HKDF.hpp>
#include <crypto/AesGcm.hpp>
#include <stdexcept>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <array>
using namespace std;
namespace transport {
    SecureSession::SecureSession():client_public_key(), client_secret_key(), session_key(), authenticated(false), send_counter(0), receive_counter(0), dilithium_pk(), dilithium_sk(), peer_dilithium_pk(), handshake_transcript() {}
    array<uint8_t,12> SecureSession::make_nonce(uint64_t counter){
        return util::make_nonce(counter); // just calling the nonce method from util because of prior wrong placement of the function
    }
    void SecureSession::set_client_keypair(const vector <uint8_t> &pk, const vector <uint8_t> &sk) { // setting key for the session
        client_public_key = pk;
        client_secret_key = sk;
    }
    vector<uint8_t> SecureSession::server_handle_public_key(const vector<uint8_t>&client_pk){
        if(client_pk.empty())
            throw runtime_error("the client public key is empty");
        crypto::KeyExchange kem; // keyexchange instance
        auto pair_ct_ss =kem.encapsulate(client_pk); // we get the ct and ss
        vector<uint8_t> ct = pair_ct_ss.first;
        vector<uint8_t> ss = pair_ct_ss.second;
        crypto::HKDF hkdf; // hkdf instance
        vector<uint8_t> info = {'s', 'e', 'r', 'v', 'e', 'r'}; // info for the HKDF
        session_key = hkdf.derive(ss, {}, info, 32); // deriving the session key
        if(session_key.size() != 32)
            throw runtime_error("the session key is either empty or of the wrong size");
        
        authenticated = true; // we set the session as authenticated
        send_counter = 0;
        receive_counter =0;
        return ct; // returning the ciphertext
    }
    void SecureSession::client_process_server_hello(const vector<uint8_t> &server_ct){
        if(client_secret_key.empty())
            throw runtime_error("the client secret key is empty (from client server hello)");
        if(server_ct.empty())
            throw runtime_error("the server ciphertext is empty (from client server hello)");
        crypto::KeyExchange kem; // keyexchange instance
        vector<uint8_t> ss = kem.decapsulate(server_ct, client_secret_key);
        crypto::HKDF hkdf; // hkdf instance
        vector<uint8_t> info ={'s','e','r','v','e','r'};
        session_key = hkdf.derive(ss, {}, info, 32); // deriving the session key
        if(session_key.size() != 32)
            throw runtime_error("the session key is either empty or of the wrong size (from client server hello)");
        authenticated = true; // we set the session as authenticated
        send_counter = 0;
        receive_counter = 0;
    }
    vector<uint8_t> SecureSession::encrypt_packet(const vector<uint8_t>& packet, const vector<uint8_t>& aad) {
        if(!authenticated)
            throw runtime_error("session is not authenticated");
        if(packet.empty())
            throw runtime_error("the packet to encrypt is empty");
        send_counter++;
        crypto::AesGcm aesgcm; // AES GCM instance
        array<uint8_t, 12> nonce = make_nonce(send_counter); // create nonce
        vector<uint8_t> nonce_vec(nonce.begin(), nonce.end()); // convert nonce to vector
        auto encrypted = aesgcm.encrypt(packet, session_key, nonce_vec, aad); // encrypt the packet
        vector<uint8_t> ciphertext = encrypted.first;
        vector<uint8_t> auth_tag = encrypted.second;
        /***
         * Wire Packet
         * type(1)
         * payload length(4)
         * nonce(12)
         * ciphertext
         * authentication tag
         */
        uint32_t len = static_cast<uint32_t>(ciphertext.size());
        vector<uint8_t> wire_pac;
        wire_pac.reserve(1 + 4 + 12 + len + auth_tag.size());
        wire_pac.push_back(static_cast<uint8_t>(0x10)); // type
        wire_pac.push_back(static_cast<uint8_t>((len >> 24) & 0xFF)); // length
        wire_pac.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        wire_pac.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        wire_pac.push_back(static_cast<uint8_t>((len) & 0xFF));
        wire_pac.insert(wire_pac.end(), nonce_vec.begin(), nonce_vec.end()); // nonce
        wire_pac.insert(wire_pac.end(), ciphertext.begin(), ciphertext.end()); // ciphertext
        wire_pac.insert(wire_pac.end(), auth_tag.begin(), auth_tag.end()); // authentication tag
        return wire_pac;
    }
    vector<uint8_t> SecureSession::decrypt_packet(const vector<uint8_t>& packet, const vector<uint8_t>& aad) {
        if(!authenticated)
            throw runtime_error("session is not authenticated");
        if(packet.size()<33) // minimum size is 33 due to 1(type) + 4(len) + 12(nonce) + auth_tag(16)
            throw runtime_error("the packet to decrypt is invalid due to it being too small");
        size_t offset =0;
        uint8_t type = packet[offset++];
        if(type != 0x10) // checking type
            throw runtime_error("the packet type is invalid");
        uint32_t len = (static_cast<uint32_t>(packet[offset]) << 24) | (static_cast<uint32_t>(packet[offset + 1]) << 16) | (static_cast<uint32_t>(packet[offset + 2]) << 8) | (static_cast<uint32_t>(packet[offset + 3]));
        offset += 4; // move past length
        size_t total = 1+4+12+len+16; //expected total with the payload len now added
        if(packet.size() < total)
            throw runtime_error("the packet to decrypt is invalid due to it being too small");
        array<uint8_t, 12> nonce_arr;
        copy_n(packet.begin()+offset, 12, nonce_arr.begin());
        offset += 12; // move past nonce
        vector<uint8_t> ct;
        ct.insert(ct.end(), packet.begin() + offset, packet.begin() + offset + len); // ciphertext
        offset += len; // move past ciphertext
        vector<uint8_t> auth_tag;
        auth_tag.insert(auth_tag.end(), packet.begin() + offset, packet.begin() + offset + 16); // authentication tag
        offset += 16; // move past auth tag
        uint64_t counter = 0;
        for(int i=4;i<12;i++) {
            counter = (counter << 8) | nonce_arr[i];
        }
        if(counter<=receive_counter) {
            throw runtime_error("the packet nonce is invalid due to it being less than or equal to the receive counter");
        }
        crypto::AesGcm aesgcm; // AES GCM instance
        vector<uint8_t> nonce_vec(nonce_arr.begin(), nonce_arr.end()); // convert nonce to vector
        vector<uint8_t> decrypted = aesgcm.decrypt(ct, auth_tag, session_key, nonce_vec, aad);
        receive_counter = counter;
        return decrypted;
    }
    bool SecureSession::is_authenticated() const {
        return authenticated;
    }
    void SecureSession::generate_dilithium_keys() {
        auto kp = crypto::KeyExchange::generate_dilithium_keypair();
        dilithium_pk = kp.first;
        dilithium_sk = kp.second;
    }
    void SecureSession::set_dilithium_keypair(const vector<uint8_t>& pk, const vector<uint8_t>& sk) {
        dilithium_pk = pk;
        dilithium_sk = sk;
    }
    vector<uint8_t> SecureSession::server_handle_public_key_authenticated(const vector<uint8_t>& client_pk, const vector<uint8_t>& client_dili_pk) {
        if(client_pk.empty())
            throw runtime_error("the client public key is empty");
        if(client_dili_pk.empty())
            throw runtime_error("the client dilithium public key is empty");
        // generate our own dilithium keys if not already set
        if(dilithium_pk.empty())
            generate_dilithium_keys();
        // store peer dilithium pk
        peer_dilithium_pk = client_dili_pk;
        // do the normal kyber encapsulation
        auto pair_ct_ss = crypto::KeyExchange::encapsulate(client_pk);
        vector<uint8_t> ct = pair_ct_ss.first;
        vector<uint8_t> ss = pair_ct_ss.second;
        // build transcript = client_pk || ct for signing
        vector<uint8_t> transcript;
        transcript.insert(transcript.end(), client_pk.begin(), client_pk.end());
        transcript.insert(transcript.end(), ct.begin(), ct.end());
        // store transcript for later client signature verification
        handshake_transcript = transcript;
        // sign the transcript with our dilithium sk
        vector<uint8_t> signature = crypto::KeyExchange::sign_handshake_transcript(dilithium_sk, transcript);
        // derive session key using HKDF with signature as salt for stronger binding
        crypto::HKDF hkdf;
        vector<uint8_t> info = {'s', 'e', 'r', 'v', 'e', 'r'};
        session_key = hkdf.derive(ss, signature, info, 32);
        if(session_key.size() != 32)
            throw runtime_error("session key derivation failed");
        // pack response: ct_len(4) || ct || dilithium_pk || signature
        vector<uint8_t> response;
        uint32_t ct_len = static_cast<uint32_t>(ct.size());
        response.push_back(static_cast<uint8_t>((ct_len >> 24) & 0xFF));
        response.push_back(static_cast<uint8_t>((ct_len >> 16) & 0xFF));
        response.push_back(static_cast<uint8_t>((ct_len >> 8) & 0xFF));
        response.push_back(static_cast<uint8_t>(ct_len & 0xFF));
        response.insert(response.end(), ct.begin(), ct.end());
        response.insert(response.end(), dilithium_pk.begin(), dilithium_pk.end());
        response.insert(response.end(), signature.begin(), signature.end());
        // dont set authenticated yet - wait for client signature verification
        send_counter = 0;
        receive_counter = 0;
        return response;
    }
    vector<uint8_t> SecureSession::client_process_server_hello_authenticated(
        const vector<uint8_t>& server_ct,
        const vector<uint8_t>& server_dili_pk,
        const vector<uint8_t>& server_signature,
        const vector<uint8_t>& original_client_pk
    ) {
        if(client_secret_key.empty())
            throw runtime_error("the client secret key is empty");
        if(server_ct.empty())
            throw runtime_error("the server ciphertext is empty");
        if(server_dili_pk.empty())
            throw runtime_error("the server dilithium pk is empty");
        if(server_signature.empty())
            throw runtime_error("the server signature is empty");
        // store server dilithium pk
        peer_dilithium_pk = server_dili_pk;
        // verify server signature over transcript = client_pk || ct
        vector<uint8_t> transcript;
        transcript.insert(transcript.end(), original_client_pk.begin(), original_client_pk.end());
        transcript.insert(transcript.end(), server_ct.begin(), server_ct.end());
        if(!crypto::KeyExchange::verify_handshake_signature(server_dili_pk, server_signature, transcript))
            throw runtime_error("server signature verification failed - possible MITM");
        // decapsulate to get shared secret
        vector<uint8_t> ss = crypto::KeyExchange::decapsulate(server_ct, client_secret_key);
        // derive session key using same HKDF with signature as salt
        crypto::HKDF hkdf;
        vector<uint8_t> info = {'s', 'e', 'r', 'v', 'e', 'r'};
        session_key = hkdf.derive(ss, server_signature, info, 32);
        if(session_key.size() != 32)
            throw runtime_error("session key derivation failed");
        // generate our own dilithium keys if not set, then sign the transcript for mutual auth
        if(dilithium_pk.empty())
            generate_dilithium_keys();
        // client signs transcript = client_pk || ct (same data) to prove identity back to server
        vector<uint8_t> client_sig = crypto::KeyExchange::sign_handshake_transcript(dilithium_sk, transcript);
        authenticated = true;
        send_counter = 0;
        receive_counter = 0;
        return client_sig;
    }
    bool SecureSession::server_verify_client_signature(const vector<uint8_t>& client_signature, const vector<uint8_t>& server_ct) {
        if(peer_dilithium_pk.empty())
            return false;
        if(handshake_transcript.empty())
            return false;
        // verify client signature over the stored transcript (client_pk || ct)
        if(!crypto::KeyExchange::verify_handshake_signature(peer_dilithium_pk, client_signature, handshake_transcript))
            return false;
        authenticated = true;
        return true;
    }
}