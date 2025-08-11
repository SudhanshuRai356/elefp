#include<iostream>
#include<vector>
#include<string>
#include<asio.hpp>
#include<transport/SecureSession.hpp>
#include<crypto/KeyExchange.hpp>
using namespace std;
int main(){
    try{
        asio::io_context io;
        asio::ip::udp::socket socket(io);
        socket.open(asio::ip::udp::v4());
        asio::ip::udp::endpoint endpt(asio::ip::make_address("127.0.0.1"), 9000);
        transport::SecureSession session;
        crypto::KeyExchange kem;
        auto keypair = kem.generate_keypair();
        session.set_client_keypair(keypair.first, keypair.second);
        vector<uint8_t>hello;
        hello.push_back(0x01);
        hello.insert(hello.end(),keypair.first.begin(), keypair.first.end());
        socket.send_to(asio::buffer(hello), endpt);
        cout << "Sent client public key to server." << endl;
        vector<uint8_t> recvbuff(8192);
        asio::ip::udp::endpoint sender_endpoint;
        size_t len = socket.receive_from(asio::buffer(recvbuff), sender_endpoint);
        cout << "Received " << len << " bytes from server." << endl;
        if(len<2||recvbuff[0]!=0x02){
            cerr << "Invalid response from server." << endl;
            return 1;
        }
        vector<uint8_t> server_ct(recvbuff.begin() + 1, recvbuff.begin() + len);
        session.client_process_server_hello(server_ct);
        cout<<"Server hello was successful."<<endl;
        string msg = "dheeraj bkl hai!";
        vector<uint8_t>pkt=session.encrypt_packet(vector<uint8_t>(msg.begin(), msg.end()));
        socket.send_to(asio::buffer(pkt), endpt);
        cout << "Sent encrypted packet to server." << endl;
        return 0;
    }
    catch(const std::exception& e){
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
}