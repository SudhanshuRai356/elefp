#include <iostream>
#include <string>
#include <vector>
#include<thread>
#include <chrono>
#include <mutex>
#include<unordered_map>
#include <atomic>
#include <memory>

#include<asio.hpp>
#include "transport/SecureSession.hpp"
#include "transport/SessionManager.hpp"
#include "crypto/KeyExchange.hpp"

using namespace std;
#define u uint8_t
namespace swarm{
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
        control_station(asio::io_context &io,int port=9000): socket_(io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), static_cast<unsigned int>(port))),
        mgr_(), // session manager cotr
        id_alloc_(), // id allocator cotr
        stopping_(false) //atomic stopping flag
        {
            cout<<"[ground]control_station created on port "<<port<<endl;
        }
        void run_loop(){ //main recieve loop
            vector<u> recvbuff(8192);
            asio::ip::udp::endpoint sender_endpoint;
            while(!stopping_.load()){
                try{
                    size_t n=socket_.receive_from(asio::buffer(recvbuff),sender_endpoint);
                    if(n==0)
                    continue; // if no data is recieved
                    u type =recvbuff[0];
                    string rkey=ep_key(sender_endpoint);
                    if(type==MSG_Client_Hello){ //initiating handshake
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
                        vector<u> enc(recvbuff.begin()+1, recvbuff.begin()+n); //load encrypted data
                        try{
                            vector<u>dec=session_ptr->decrypt_packet(enc); //decrypt enc data
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
                    cerr<<"[ground] error in control station loop: "<<e.what()<<endl;
                }
            }
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
            asio::error_code ec;
            socket_.close(ec); //close the socket
        }
        private:
        asio::ip::udp::socket socket_; //udp socket for communication
        std::atomic<bool> stopping_; //flag to indicate stopping
        ID_Allocator id_alloc_; //id allocator for leads
        transport::SessionManager mgr_; //session manager for handling sessions
        unordered_map<string,int> endpoint_to_id_; //map from endpoint to id
        unordered_map<int,asio::ip::udp::endpoint> id_to_endpoint_; //map from id to endpoint
    };
}
int main(){
    try{
        asio::io_context io;
        swarm::control_station station(io, 9000); //create control station on port 9000
        thread t([&station](){ //run the control station in a separate thread
            station.run_loop();
        });
        cout<<"[main] ground station will run for 3 seconds as will be evident ... so that the leads and follower may be put on other threads by the program"<<endl;
        this_thread::sleep_for(std::chrono::seconds(3)); // let the station run for 3 seconds
        station.broadcast_to_leads("Mission 0: please work and make sure to past all the tests without error");
        station.stop(); //stop the station thread
        if(t.joinable()){
            t.join(); //waits for the thread to finish before running the join
        }
        cout<<"[main] ground station has stopped and all the tests are run successfully"<<endl;
    }
    catch(const std::exception &e){
        cerr<<"[main] error: "<<e.what()<<endl;
    }
}