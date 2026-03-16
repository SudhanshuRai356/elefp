#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <stdexcept>
#include <functional>
#include "crypto/KeyExchange.hpp"
#include "transport/SecureSession.hpp"

using namespace std;

static int tests_passed = 0;
static int tests_failed = 0;

void run_test(const string& name, function<void()> fn) {
    cout << "  [TEST] " << name << "... ";
    try {
        fn();
        cout << "PASSED" << endl;
        tests_passed++;
    } catch (const exception& e) {
        cout << "FAILED: " << e.what() << endl;
        tests_failed++;
    }
}

// Helper to do authenticated handshake between two sessions
struct HandshakeResult {
    vector<uint8_t> ct;
    vector<uint8_t> srv_dili_pk;
    vector<uint8_t> srv_sig;
};

HandshakeResult unpack_server_response(const vector<uint8_t>& packed) {
    HandshakeResult r;
    uint32_t ct_len = (uint32_t(packed[0]) << 24) | (uint32_t(packed[1]) << 16) |
                      (uint32_t(packed[2]) << 8) | uint32_t(packed[3]);
    size_t offset = 4;
    r.ct.assign(packed.begin()+offset, packed.begin()+offset+ct_len);
    offset += ct_len;
    const size_t DILI_PK_SIZE = 1312;
    r.srv_dili_pk.assign(packed.begin()+offset, packed.begin()+offset+DILI_PK_SIZE);
    offset += DILI_PK_SIZE;
    r.srv_sig.assign(packed.begin()+offset, packed.end());
    return r;
}

int main() {
    cout << "=== Dilithium (ML-DSA-44) Integration Tests ===" << endl;
    cout << endl;

    cout << "[Crypto Layer Tests]" << endl;

    run_test("ML-DSA-44 keypair generation", []() {
        auto kp = crypto::KeyExchange::generate_dilithium_keypair();
        if (kp.first.empty()) throw runtime_error("public key is empty");
        if (kp.second.empty()) throw runtime_error("secret key is empty");
        cout << "(pk=" << kp.first.size() << " sk=" << kp.second.size() << ") ";
    });

    run_test("ML-DSA-44 sign and verify", []() {
        auto kp = crypto::KeyExchange::generate_dilithium_keypair();
        vector<uint8_t> msg = {'h','e','l','l','o',' ','w','o','r','l','d'};
        auto sig = crypto::KeyExchange::sign_handshake_transcript(kp.second, msg);
        if (sig.empty()) throw runtime_error("signature is empty");
        bool ok = crypto::KeyExchange::verify_handshake_signature(kp.first, sig, msg);
        if (!ok) throw runtime_error("valid signature rejected");
    });

    run_test("ML-DSA-44 reject bad signature", []() {
        auto kp = crypto::KeyExchange::generate_dilithium_keypair();
        vector<uint8_t> msg = {'g','o','o','d'};
        auto sig = crypto::KeyExchange::sign_handshake_transcript(kp.second, msg);
        sig[0] ^= 0xFF;
        bool ok = crypto::KeyExchange::verify_handshake_signature(kp.first, sig, msg);
        if (ok) throw runtime_error("tampered signature was accepted!");
    });

    run_test("ML-DSA-44 reject wrong public key", []() {
        auto kp1 = crypto::KeyExchange::generate_dilithium_keypair();
        auto kp2 = crypto::KeyExchange::generate_dilithium_keypair();
        vector<uint8_t> msg = {'t','e','s','t'};
        auto sig = crypto::KeyExchange::sign_handshake_transcript(kp1.second, msg);
        bool ok = crypto::KeyExchange::verify_handshake_signature(kp2.first, sig, msg);
        if (ok) throw runtime_error("wrong key accepted the signature!");
    });

    run_test("ML-DSA-44 reject wrong message", []() {
        auto kp = crypto::KeyExchange::generate_dilithium_keypair();
        vector<uint8_t> msg1 = {'a','b','c'};
        vector<uint8_t> msg2 = {'x','y','z'};
        auto sig = crypto::KeyExchange::sign_handshake_transcript(kp.second, msg1);
        bool ok = crypto::KeyExchange::verify_handshake_signature(kp.first, sig, msg2);
        if (ok) throw runtime_error("wrong message accepted!");
    });

    cout << endl;
    cout << "[SecureSession Authenticated Handshake Tests]" << endl;

    run_test("Full authenticated handshake", []() {
        transport::SecureSession client_session;
        transport::SecureSession server_session;

        auto kyber_kp = crypto::KeyExchange::generate_keypair();
        client_session.set_client_keypair(kyber_kp.first, kyber_kp.second);
        client_session.generate_dilithium_keys();

        vector<uint8_t> packed = server_session.server_handle_public_key_authenticated(
            kyber_kp.first, client_session.get_dilithium_pk());

        auto r = unpack_server_response(packed);

        vector<uint8_t> client_sig = client_session.client_process_server_hello_authenticated(
            r.ct, r.srv_dili_pk, r.srv_sig, kyber_kp.first);

        if (client_sig.empty()) throw runtime_error("client signature is empty");
        if (!client_session.is_authenticated()) throw runtime_error("client not authenticated");

        bool srv_ok = server_session.server_verify_client_signature(client_sig, r.ct);
        if (!srv_ok) throw runtime_error("server rejected valid client signature");
        if (!server_session.is_authenticated()) throw runtime_error("server not authenticated");
    });

    run_test("Authenticated handshake then encrypt/decrypt", []() {
        transport::SecureSession client_session;
        transport::SecureSession server_session;

        auto kyber_kp = crypto::KeyExchange::generate_keypair();
        client_session.set_client_keypair(kyber_kp.first, kyber_kp.second);
        client_session.generate_dilithium_keys();

        vector<uint8_t> packed = server_session.server_handle_public_key_authenticated(
            kyber_kp.first, client_session.get_dilithium_pk());
        auto r = unpack_server_response(packed);

        vector<uint8_t> client_sig = client_session.client_process_server_hello_authenticated(
            r.ct, r.srv_dili_pk, r.srv_sig, kyber_kp.first);
        server_session.server_verify_client_signature(client_sig, r.ct);

        vector<uint8_t> plaintext = {'H','e','l','l','o',' ','D','i','l','i','t','h','i','u','m','!'};
        vector<uint8_t> encrypted = client_session.encrypt_packet(plaintext);
        vector<uint8_t> decrypted = server_session.decrypt_packet(encrypted);
        if (decrypted != plaintext) throw runtime_error("decrypted data does not match original");

        vector<uint8_t> plaintext2 = {'R','e','p','l','y','!'};
        vector<uint8_t> encrypted2 = server_session.encrypt_packet(plaintext2);
        vector<uint8_t> decrypted2 = client_session.decrypt_packet(encrypted2);
        if (decrypted2 != plaintext2) throw runtime_error("reverse direction decryption failed");
    });

    run_test("MITM detection - tampered server signature", []() {
        transport::SecureSession client_session;
        transport::SecureSession server_session;

        auto kyber_kp = crypto::KeyExchange::generate_keypair();
        client_session.set_client_keypair(kyber_kp.first, kyber_kp.second);
        client_session.generate_dilithium_keys();

        vector<uint8_t> packed = server_session.server_handle_public_key_authenticated(
            kyber_kp.first, client_session.get_dilithium_pk());
        auto r = unpack_server_response(packed);

        r.srv_sig[0] ^= 0xFF; // tamper

        bool caught = false;
        try {
            client_session.client_process_server_hello_authenticated(
                r.ct, r.srv_dili_pk, r.srv_sig, kyber_kp.first);
        } catch (const runtime_error& e) {
            string msg = e.what();
            if (msg.find("MITM") != string::npos || msg.find("signature") != string::npos)
                caught = true;
        }
        if (!caught) throw runtime_error("MITM attack was not detected!");
    });

    cout << endl;
    cout << "=== Results: " << tests_passed << " passed, " << tests_failed << " failed ===" << endl;
    return tests_failed > 0 ? 1 : 0;
}
