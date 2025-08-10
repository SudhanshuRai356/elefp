#include "transport/SessionManager.hpp"
using namespace std;
namespace transport {
    shared_ptr<SecureSession> SessionManager::create_session(int client_id) {
        auto session = make_shared<SecureSession>();
        sessions[client_id] = session; // store the session in the map
        return session;
    }
    shared_ptr<SecureSession> SessionManager::get_session(int client_id) {
        auto it = sessions.find(client_id);
        if (it != sessions.end()) {
            return it->second;
        }
        return nullptr;
    }
    void SessionManager::remove_session(int client_id) {
        sessions.erase(client_id); // remove the session from the map
    }
}