#include <iostream>
#include <vector>
#include <string>
#include <asio.hpp>
#include <transport/SecureSession.hpp>
#include <transport/SessionManager.hpp>

using namespace std;
int main(){
    try{
        asio::io_context io;
        asio::ip::udp::socket socket(io,asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 9000));
        std::cout<<"the udp is being listened to at 127.0.0.1:9000"<<std::endl;
        transport::SessionManager secureManager;
        asio::ip::udp::endpoint endpt;
        vector<uint8_t> recvbuff(8192);
        size_t n=socket.receive_from(asio::buffer(recvbuff),endpt);// recieving client public key
        std::cout<<"recieved "<<n<<" bytes from the client from "<<endpt.address().to_string()<<":"<<endpt.port()<<std::endl;
        if(n<2 || recvbuff[0]!=0x01){
            std::cout<<"received either wrong type or malformed data"<<std::endl;
            return 1;
        }
        vector<uint8_t>client_pk(recvbuff.begin()+1,recvbuff.begin()+n);
        auto session = secureManager.create_session(1);//generating session
        vector<uint8_t> server_ct = session->server_handle_public_key(client_pk);//using client public key to derive an ciphertext and shared secret
        vector<uint8_t> sendbuff;
        sendbuff.push_back(0x02); // type
        sendbuff.insert(sendbuff.end(), server_ct.begin(), server_ct.end());
        socket.send_to(asio::buffer(sendbuff), endpt); //sending server ciphertext and shared secret
        cout<<"sent "<<sendbuff.size()<<" bytes to the client"<<std::endl;
        n=socket.receive_from(asio::buffer(recvbuff), endpt);  // recieving encrypted message
        std::cout<<"recieved "<<n<<" bytes from the client from "<<endpt.address().to_string()<<":"<<endpt.port()<<std::endl;
        vector<uint8_t> enc_packet(recvbuff.begin(), recvbuff.begin() + n);
        vector<uint8_t> dec_packet = session->decrypt_packet(enc_packet); // decrypting encrypted message
        cout<<"received dec packet of "<<dec_packet.size()<<" bytes from the client"<<std::endl;
        string msg(dec_packet.begin(), dec_packet.end());
        cout<<"decrypted message: "<<msg<<endl;
        return 0;
    }
    catch(const std::exception& e){
        std::cerr<<"Exception: "<<e.what()<<std::endl;
        return 1;
    }
}
