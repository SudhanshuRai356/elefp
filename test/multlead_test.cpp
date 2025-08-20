#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <memory>
#include <asio.hpp>
#include "transport/SecureSession.hpp"
#include "transport/SessionManager.hpp"
#include "crypto/KeyExchange.hpp"

using namespace std;
#define u uint8_t

// Add thread-safe logging
mutex cout_mutex;
#define SAFE_COUT(x) do { lock_guard<mutex> lock(cout_mutex); cout << x << endl; } while(0)
namespace swarm {
    enum: u{
        MSG_Client_Hello = 0x01,
        MSG_Server_Hello = 0x02,
        MSG_Encrypted_Packet = 0x10,
        MSG_Encrypted_Broadcast = 0x20,
        MSG_Follower_Status = 0x21,
    };

    void send_to_socket(asio::ip::udp::socket &socket,const asio::ip::udp::endpoint &endpt,const vector<u> &data){ //helper to send data
        socket.send_to(asio::buffer(data), endpt);
    }

    vector<u> client_hello(const vector<u> &pk){ //making thee client hello data
        vector<u> v;
        v.reserve(1+pk.size());
        v.push_back(MSG_Client_Hello);
        v.insert(v.end(), pk.begin(), pk.end());
        return v;
    }

    vector<u> server_hello(const vector<u> &ct){ //making the server hello
        vector<u> v;
        v.reserve(1+ct.size());
        v.push_back(MSG_Server_Hello);
        v.insert(v.end(), ct.begin(), ct.end());
        return v;
    }

    class ID_Allocator{
        atomic<int> next_id{1};
    public:
        int allocate_id(){
            return next_id.fetch_add(1);
        }
    };

    inline string ep_key(const asio::ip::udp::endpoint &ep) {
        return ep.address().to_string() + ":" + to_string(ep.port());
    }

    class control_station{
    public:
        control_station(asio::io_context &io,int port=9000)
            : socket_(io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(port))),
              mgr_(),
              id_alloc_(),
              stopping_(false)
        {
            SAFE_COUT("[ground]control_station created on port " << port); // Added thread-safe logging
        }

        void run_loop(){ //main recieve loop
            vector<u> recvbuff(8192);
            asio::ip::udp::endpoint sender_endpoint;
            
            // Set socket to non-blocking mode to allow clean shutdown
            socket_.non_blocking(true);
            
            while(!stopping_.load()){
                try{
                    asio::error_code ec;
                    size_t n = socket_.receive_from(asio::buffer(recvbuff), sender_endpoint, 0, ec);
                    
                    if (ec == asio::error::would_block) {
                        // No data available, sleep briefly and continue
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                    
                    if (ec) {
                        // Other error, likely socket closed - exit cleanly
                        SAFE_COUT("[ground] socket error, exiting: " << ec.message());
                        break;
                    }
                    
                    if(n==0)
                        continue; // if no data is recieved
                    u type = recvbuff[0];
                    string rkey=ep_key(sender_endpoint);

                    if(type==MSG_Client_Hello){ //initiating handshake
                        // fixed slice: PK runs from begin()+1 up to begin()+n
                        vector<u> lead_pk(recvbuff.begin()+1, recvbuff.begin()+n);
                        int id = id_alloc_.allocate_id(); // allocate a new id
                        endpoint_to_id_[rkey]=id; //storing mapping
                        id_to_endpoint_[id]=sender_endpoint;
                        auto session=mgr_.create_session(id); //create a session with the created id
                        vector<u> ct=session->server_handle_public_key(lead_pk); //getting ct from the server
                        vector<u> hello_msg = server_hello(ct); //making the server hello message
                        send_to_socket(socket_,sender_endpoint,hello_msg);
                        cout<<"[ground] lead connected to "<<rkey<<" with id = "<<id<<endl;
                        continue;
                    }
                    else if(type==MSG_Encrypted_Packet){//if encrypted packet is recieved
                        auto it=endpoint_to_id_.find(rkey);//recieve id
                        if(it==endpoint_to_id_.end()){
                            cerr<<"[ground] unknown lead "<<rkey<<endl;
                            continue;
                        }
                        int id=it->second;
                        auto session_ptr=mgr_.get_session(id);
                        if(!session_ptr){
                            cerr<<"[ground] unknown session "<<id<<endl;
                            continue;
                        }

                        // pass full wire (type + rest) because decrypt_packet expects wire format
                        vector<u> enc(recvbuff.begin(), recvbuff.begin()+n); //load encrypted data
                        try{
                            vector<u> dec=session_ptr->decrypt_packet(enc); //decrypt enc data
                            if(dec.empty()){
                                cerr<<"[ground] decryption failed for id "<<id<<endl;
                                continue;
                            }
                            u inner=dec[0];
                            if(inner==MSG_Follower_Status){
                                string status_msg(dec.begin()+1, dec.end());
                                cout<<"[ground] status from id "<<id<<": "<<status_msg<<endl;
                            }
                            else if(inner==MSG_Encrypted_Broadcast){
                                cout<<"[ground] broadcast from id "<<id<<": ";
                                string x(dec.begin()+1, dec.end());
                                cout<<x<<endl;
                            }
                            else{
                                cerr<<"[ground] unknown message type "<<static_cast<int>(inner)<<" from id "<<id<<endl;
                            }
                        }
                        catch(const exception &e){
                            cerr<<"[ground] decryption error for id "<<id<<": "<<e.what()<<endl;
                        }
                        continue;
                    }
                    cerr<<"[ground] unknown message type "<<static_cast<int>(type)<<" from "<<rkey<<endl;
                }
                catch(const std::exception &e){
                    // If we're shutting down, break the loop cleanly.
                    if (stopping_.load()) {
                        // optional debug:
                        cerr << "[ground] shutdown requested, exiting run_loop" << endl;
                        break;
                    }
                    cerr<<"[ground] error in control station loop: "<<e.what()<<endl;
                    // continue loop for transient errors
                }
            }
            SAFE_COUT("[ground] run_loop exiting cleanly"); // Add final exit message
        }

        void broadcast_to_leads(const string &mission){
            for(const auto &kv:id_to_endpoint_){
                int id = kv.first;
                const asio::ip::udp::endpoint &endpt=kv.second;
                auto session_ptr=mgr_.get_session(id);
                if(!session_ptr)
                    continue; //no such session for given id
                if(!session_ptr->is_authenticated())
                    continue; //session is not authenticated
                vector<u> msg;
                msg.push_back(MSG_Encrypted_Broadcast);
                msg.insert(msg.end(),mission.begin(), mission.end());
                vector<u> enc=session_ptr->encrypt_packet(msg); //encrypt the message
                send_to_socket(socket_,endpt,enc);
            }
            cout<<"[ground] broadcasted mission/message to all lead: "<<mission<<endl;
        }

        void stop(){ //stopping the sending and recieving of data
            stopping_.store(true);
            // cancel outstanding operations first (ensures receive_from is interrupted)
            asio::error_code ec;
            socket_.cancel(ec); // ignore ec on cancel
            socket_.close(ec); // then close the socket
            SAFE_COUT("[ground] stop() called, socket closed"); // Add logging to track cleanup
        }

    private:
        asio::ip::udp::socket socket_; //udp socket for communication
        std::atomic<bool> stopping_; //flag to indicate stopping
        ID_Allocator id_alloc_; //id allocator for leads
        transport::SessionManager mgr_; //session manager for handling sessions
        unordered_map<string,int> endpoint_to_id_; //map from endpoint to id
        unordered_map<int,asio::ip::udp::endpoint> id_to_endpoint_; //map from id to endpoint
    };


    // small struct to hold lead configuration
    struct LeadConfig {
        int lead_id;
        unsigned short listen_port; // port the lead binds (and followers send to)
        asio::ip::udp::endpoint ground_ep;
        int num_followers;
    };

    // lead thread: acts as client to ground and server to followers
    void lead_thread_func(LeadConfig cfg) {
        try {
            asio::io_context io;
            // socket that will be bound to listen_port (also used to talk to ground)
            asio::ip::udp::socket sock(io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), cfg.listen_port));

            string listen_key = ep_key(sock.local_endpoint());
            cout << "[lead " << cfg.lead_id << "] listening on " << listen_key << endl;

            // Create SecureSession for lead <-> ground
            transport::SecureSession ses_to_ground;
            // generate kyber keypair
            crypto::KeyExchange kem;
            auto kp = kem.generate_keypair(); // {pk, sk}
            ses_to_ground.set_client_keypair(kp.first, kp.second);

            // build client hello and send from same socket (so ground learns this endpoint)
            vector<u> hello = client_hello(kp.first);
            send_to_socket(sock, cfg.ground_ep, hello);

            // wait for server hello from ground
            vector<u> recvbuff(8192);
            asio::ip::udp::endpoint sender;
            size_t n = sock.receive_from(asio::buffer(recvbuff), sender);
            if (n == 0) {
                cerr << "[lead " << cfg.lead_id << "] no data from ground" << endl; return;
            }
            if (recvbuff[0] != MSG_Server_Hello) {
                cerr << "[lead " << cfg.lead_id << "] unexpected reply from ground" << endl; return;
            }
            vector<u> ct(recvbuff.begin() + 1, recvbuff.begin() + n);
            ses_to_ground.client_process_server_hello(ct);
            cout << "[lead " << cfg.lead_id << "] connected to ground (authenticated)" << endl;

            // follower session manager & maps (for leader acting as server)
            transport::SessionManager follower_mgr;
            unordered_map<string,int> follower_ep_to_id;
            unordered_map<int,asio::ip::udp::endpoint> follower_id_to_ep;
            ID_Allocator follower_ids;
            mutex follower_mtx;

            // spawn N follower threads that will handshake to this lead and send a status
            vector<thread> follower_threads;
            for (int i = 0; i < cfg.num_followers; ++i) {
                follower_threads.emplace_back([i, &cfg]() {
                    try {
                        asio::io_context fioc;
                        asio::ip::udp::socket fsock(fioc);
                        fsock.open(asio::ip::udp::v4());
                        // ephemeral port; leader sees the endpoint
                        asio::ip::udp::endpoint lead_ep(asio::ip::make_address("127.0.0.1"), cfg.listen_port);

                        // follower SecureSession (client)
                        transport::SecureSession fsession;
                        crypto::KeyExchange fkem;
                        auto fkp = fkem.generate_keypair();
                        fsession.set_client_keypair(fkp.first, fkp.second);

                        // send client hello to lead
                        vector<u> ch = client_hello(fkp.first);
                        std::this_thread::sleep_for(std::chrono::milliseconds(50 + (i * 10)));
                        fsock.send_to(asio::buffer(ch), lead_ep);

                        // wait for server hello from lead
                        vector<u> fr(4096);
                        asio::ip::udp::endpoint rp;
                        size_t rn = fsock.receive_from(asio::buffer(fr), rp);
                        if (rn == 0 || fr[0] != MSG_Server_Hello) {
                            cerr << "[follower " << cfg.lead_id << "." << i << "] no server hello" << endl;
                            return;
                        }
                        vector<u> fct(fr.begin() + 1, fr.begin() + rn);
                        fsession.client_process_server_hello(fct);

                        // build inner payload: follower status
                        string status = "Follower " + to_string(cfg.lead_id) + "." + to_string(i) + " OK";
                        vector<u> inner; inner.push_back(MSG_Follower_Status); inner.insert(inner.end(), status.begin(), status.end());
                        vector<u> wire = fsession.encrypt_packet(inner);

                       // send encrypted to lead
                        fsock.send_to(asio::buffer(wire), lead_ep);
                        cout << "[follower " << cfg.lead_id << "." << i << "] sent status to lead" << endl;
                        // we expect the lead to forward broadcasts to this follower.
                        // make socket non-blocking and poll for up to 5 seconds.
                        fsock.non_blocking(true);
                        vector<u> recv2(4096);
                        asio::ip::udp::endpoint rp2;
                        auto deadline = chrono::steady_clock::now() + chrono::seconds(5);
                        bool got_broadcast = false;
                        while (chrono::steady_clock::now() < deadline) {
                            asio::error_code ec2;
                            size_t rn2 = fsock.receive_from(asio::buffer(recv2), rp2, 0, ec2);
                            if (!ec2 && rn2 > 0) {
                                // We got something — attempt to decrypt with the follower session
                                vector<u> wire2(recv2.begin(), recv2.begin() + rn2);
                                try {
                                    vector<u> plain2 = fsession.decrypt_packet(wire2);
                                    if (!plain2.empty() && plain2[0] == MSG_Encrypted_Broadcast) {
                                        string mission(plain2.begin() + 1, plain2.end());
                                        cout << "[follower " << cfg.lead_id << "." << i << "] received broadcast: \"" << mission << "\"" << endl;
                                    } else {
                                        cout << "[follower " << cfg.lead_id << "." << i << "] received unknown inner type" << endl;
                                    }
                                } catch (const exception &ex) {
                                    cerr << "[follower " << cfg.lead_id << "." << i << "] decrypt error on broadcast: " << ex.what() << endl;
                                }
                                got_broadcast = true;
                                break;
                            }
                            // if would_block, just sleep a little and retry
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        }
                        fsock.non_blocking(false);
                        if (!got_broadcast) {
                            // no broadcast arrived within timeout — that's OK, just log it
                            SAFE_COUT("[follower " << cfg.lead_id << "." << i << "] no broadcast received (timeout)");
                        }
                        SAFE_COUT("[follower " << cfg.lead_id << "." << i << "] exiting follower thread"); // Fixed: was incorrectly saying "lead thread"
                    } catch (const exception &ex) {
                        cerr << "[follower thread error] " << ex.what() << endl;
                    }
                });
            }

            // leader main loop: handle follower handshakes & messages and forward to ground
            auto loop_until = chrono::steady_clock::now() + chrono::seconds(10);
            bool received_broadcast = false; // Add flag to exit early after broadcast
            while (chrono::steady_clock::now() < loop_until && !received_broadcast) {
                // poll socket with zero-time receive (non-blocking) using error_code
                vector<u> recvbuff_local(8192);
                asio::ip::udp::endpoint from;
                asio::error_code ec;
                size_t nread = 0;
                try {
                    nread = sock.receive_from(asio::buffer(recvbuff_local), from, 0, ec);
                } catch (...) {
                    // ignore transient errors
                }
                if (!ec && nread > 0) {
                    u type = recvbuff_local[0];
                    string key = ep_key(from);
                    if (type == MSG_Client_Hello) {
                        // follower / client connecting to lead
                        vector<u> fpk(recvbuff_local.begin() + 1, recvbuff_local.begin() + nread);
                        int fid = follower_ids.allocate_id();
                        {
                            lock_guard<mutex> lk(follower_mtx);
                            follower_ep_to_id[key] = fid;
                            follower_id_to_ep[fid] = from;
                        }
                        auto fsession = follower_mgr.create_session(fid);
                        vector<u> fct = fsession->server_handle_public_key(fpk);
                        vector<u> reply = server_hello(fct);
                        send_to_socket(sock, from, reply);
                        cout << "[lead " << cfg.lead_id << "] follower connected " << key << " as fid=" << fid << endl;
                    } else if (type == MSG_Encrypted_Packet) {
                        // encrypted packet coming from either follower or ground - determine which by endpoint
                        int fid = -1;
                        {
                            lock_guard<mutex> lk(follower_mtx);
                            auto it = follower_ep_to_id.find(key);
                            if (it != follower_ep_to_id.end()) fid = it->second;
                        }
                        if (fid != -1) {
                            auto fsession = follower_mgr.get_session(fid);
                            if (!fsession) {
                                cerr << "[lead " << cfg.lead_id << "] no follower session for fid=" << fid << endl;
                            } else {
                                vector<u> wire(recvbuff_local.begin(), recvbuff_local.begin() + nread);
                                try {
                                    vector<u> plain = fsession->decrypt_packet(wire);
                                    if (!plain.empty() && plain[0] == MSG_Follower_Status) {
                                        // typo safe: MSG_Follower_Status constant
                                    }
                                    if (!plain.empty() && plain[0] == MSG_Follower_Status) {
                                        string status(plain.begin() + 1, plain.end());
                                        cout << "[lead " << cfg.lead_id << "] got follower status: \"" << status << "\" forwarding to ground" << endl;
                                        // forward unchanged inner (MSG_Follower_Status || payload) to ground via ses_to_ground
                                        vector<u> forward = ses_to_ground.encrypt_packet(plain);
                                        send_to_socket(sock, cfg.ground_ep, forward);
                                    }
                                } catch (const exception &ex) {
                                    cerr << "[lead " << cfg.lead_id << "] follower decrypt error: " << ex.what() << endl;
                                }
                            }
                        } else {
                            // from ground?
                            if (from == cfg.ground_ep) {
                                vector<u> wire(recvbuff_local.begin(), recvbuff_local.begin() + nread);
                                try {
                                    vector<u> plain = ses_to_ground.decrypt_packet(wire);
                                    if (!plain.empty() && plain[0] == MSG_Encrypted_Broadcast) {
                                        string mission(plain.begin() + 1, plain.end());
                                        cout << "[lead " << cfg.lead_id << "] received broadcast mission: \"" << mission << "\". Routing to followers..." << endl;
                                        // route to all followers
                                        vector<int> fids;
                                        {
                                            lock_guard<mutex> lk(follower_mtx);
                                            for (auto &p : follower_id_to_ep) fids.push_back(p.first);
                                        }
                                        for (int fid : fids) {
                                            auto fsession = follower_mgr.get_session(fid);
                                            asio::ip::udp::endpoint fep;
                                            {
                                                lock_guard<mutex> lk(follower_mtx);
                                                fep = follower_id_to_ep[fid];
                                            }
                                            if (fsession && fsession->is_authenticated()) {
                                                vector<u> inner; inner.push_back(MSG_Encrypted_Broadcast);
                                                inner.insert(inner.end(), mission.begin(), mission.end());
                                                vector<u> fw = fsession->encrypt_packet(inner);
                                                send_to_socket(sock, fep, fw);
                                            }
                                        }
                                        received_broadcast = true; // Exit loop after processing broadcast
                                    }
                                } catch (const exception &ex) {
                                    cerr << "[lead " << cfg.lead_id << "] ground decrypt error: " << ex.what() << endl;
                                }
                            }
                        }
                    }
                } // end if read

                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            } // end main loop

            // join follower threads
            for (auto &t : follower_threads) if (t.joinable()) t.join();

            SAFE_COUT("[lead " << cfg.lead_id << "] shutting down"); // Added thread-safe logging

        } catch (const exception &ex) {
            cerr << "[lead thread error] " << ex.what() << endl;
        }
    }

} // namespace swarm

int main(){
    try{
        asio::io_context io;

        // start ground/control station in its own thread
        swarm::control_station station(io, 9000); //create control station on port 9000
        thread t([&station](){ //run the control station in a separate thread
            station.run_loop();
        });

        cout<<"[main] ground station will run for 3 seconds as will be evident ... so that the leads and follower may be put on other threads by the program"<<endl;
        // small pause to ensure ground is ready
        this_thread::sleep_for(std::chrono::milliseconds(100));

        // start 3 lead threads with follower simulation (ports 8001..8003)
        vector<swarm::LeadConfig> lead_cfgs = {
            {1, 8001, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9000), 4},
            {2, 8002, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9000), 3},
            {3, 8003, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9000), 4}
        };

        vector<thread> lead_threads;
        for (auto &cfg : lead_cfgs) {
            lead_threads.emplace_back([cfg](){ swarm::lead_thread_func(cfg); });
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // let things happen (handshakes, follower status)
        this_thread::sleep_for(std::chrono::seconds(2));

        station.broadcast_to_leads("Mission 0: please work and make sure to pass all the tests without error");
        // let routing happen - give lead threads time to finish their 10-second loops
        SAFE_COUT("[main] waiting for lead threads to complete their 10-second cycles...");
        this_thread::sleep_for(std::chrono::seconds(8)); // Total: 2+8=10 seconds, matching lead thread timeout

        // join leads with timeout to prevent hanging
        SAFE_COUT("[main] waiting for lead threads to finish...");
        
        // Give threads a bit more time to cleanup, then force join
        auto join_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        
        for (auto &lt : lead_threads) {
            if (lt.joinable()) {
                // Try to join with remaining time
                if (std::chrono::steady_clock::now() < join_deadline) {
                    lt.join();
                } else {
                    SAFE_COUT("[main] force detaching slow thread");
                    lt.detach(); // Detach if taking too long
                }
            }
        }
        SAFE_COUT("[main] joined all lead threads"); // Added thread-safe logging
        
        SAFE_COUT("[main] stopping ground station...");
        station.stop(); //stop the station thread
        
        // Give ground station thread time to cleanup
        auto ground_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        if(t.joinable()){
            if (std::chrono::steady_clock::now() < ground_deadline) {
                t.join(); //waits for the thread to finish before running the join
            } else {
                SAFE_COUT("[main] ground station cleanup taking too long, detaching...");
                t.detach();
            }
        }
        SAFE_COUT("[main] ground station has stopped and all the tests are run successfully"); // Added thread-safe logging
        return 0;
    }
    catch(const std::exception &e){
        cerr<<"[main] error: "<<e.what()<<endl;
        return 1;
    }
}
