#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <memory>
#include "SecureSession.hpp"
using namespace std;
namespace transport{
    class SessionManager {
        unordered_map<int,shared_ptr<SecureSession>> sessions; //map of client_id to SecureSession
        public:
        shared_ptr<SecureSession> create_session(int client_id); // creates a new session for the user
        shared_ptr<SecureSession> get_session(int client_id); // gets the seesion
        void remove_session(int client_id);// deletes a session
    };
}