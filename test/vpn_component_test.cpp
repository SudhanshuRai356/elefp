#include "vpn/TunInterface.hpp"
#include "vpn/IpPool.hpp"
#include "vpn/PacketRouter.hpp"
#include "vpn/ConfigManager.hpp"
#include "transport/SecureSession.hpp"
#include "crypto/KeyExchange.hpp"
#include <cassert>
#include <iostream>
#include <vector>
#include <cstring>

// Test TUN Interface
void test_tun_interface() {
    std::cout << "Testing TUN Interface..." << std::endl;
    
    vpn::TunInterface tun;
    
    // Test name generation
    std::string name = vpn::TunInterface::get_next_available_name("test");
    assert(!name.empty());
    std::cout << "✓ Generated TUN name: " << name << std::endl;
    
    // Note: Actual TUN interface creation requires root privileges
    // In a real test environment, these would be tested with proper permissions
    
    std::cout << "✓ TUN Interface tests passed" << std::endl;
}

// Test IP Pool
void test_ip_pool() {
    std::cout << "Testing IP Pool..." << std::endl;
    
    vpn::IpPool pool;
    
    // Add IP range
    bool added = pool.add_range("192.168.1.10", "192.168.1.20", 
                               "255.255.255.0", "192.168.1.1");
    assert(added);
    std::cout << "✓ IP range added successfully" << std::endl;
    
    // Test total IPs (excluding network and broadcast)
    size_t total = pool.total_ips();
    assert(total == 9); // 10-20 excluding .10 and .20 as network/broadcast
    std::cout << "✓ Total IPs: " << total << std::endl;
    
    // Allocate IPs
    std::string ip1 = pool.allocate_ip("client1");
    assert(!ip1.empty());
    std::cout << "✓ Allocated IP for client1: " << ip1 << std::endl;
    
    std::string ip2 = pool.allocate_ip("client2");
    assert(!ip2.empty());
    assert(ip1 != ip2);
    std::cout << "✓ Allocated IP for client2: " << ip2 << std::endl;
    
    // Test duplicate allocation
    std::string ip1_dup = pool.allocate_ip("client1");
    assert(ip1_dup == ip1);
    std::cout << "✓ Duplicate allocation returned same IP" << std::endl;
    
    // Test release
    bool released = pool.release_ip("client1");
    assert(released);
    std::cout << "✓ IP released successfully" << std::endl;
    
    // Test allocation count
    assert(pool.allocated_count() == 1);
    assert(pool.available_count() == total - 1);
    std::cout << "✓ IP counts are correct" << std::endl;
    
    // Test IP utility functions
    uint32_t ip_uint = vpn::IpPool::ip_to_uint32("192.168.1.1");
    std::string ip_str = vpn::IpPool::uint32_to_ip(ip_uint);
    assert(ip_str == "192.168.1.1");
    std::cout << "✓ IP conversion functions work" << std::endl;
    
    std::cout << "✓ IP Pool tests passed" << std::endl;
}

// Test Packet Router
void test_packet_router() {
    std::cout << "Testing Packet Router..." << std::endl;
    
    vpn::PacketRouter router;
    
    // Add clients
    router.add_client("client1", vpn::PacketRouter::ip_string_to_uint32("10.8.0.2"));
    router.add_client("client2", vpn::PacketRouter::ip_string_to_uint32("10.8.0.3"));
    
    assert(router.has_client("client1"));
    assert(router.has_client("client2"));
    std::cout << "✓ Clients added successfully" << std::endl;
    
    // Test IP to client mapping
    std::string client = router.get_client_for_ip(vpn::PacketRouter::ip_string_to_uint32("10.8.0.2"));
    assert(client == "client1");
    std::cout << "✓ IP to client mapping works" << std::endl;
    
    // Test client to IP mapping
    uint32_t ip = router.get_ip_for_client("client2");
    assert(ip == vpn::PacketRouter::ip_string_to_uint32("10.8.0.3"));
    std::cout << "✓ Client to IP mapping works" << std::endl;
    
    // Test IP header validation
    std::vector<uint8_t> valid_packet = {
        0x45, 0x00, 0x00, 0x1C,  // Version=4, IHL=5, ToS=0, Total Length=28
        0x00, 0x01, 0x40, 0x00,  // ID=1, Flags=0x4000 (Don't Fragment), Fragment Offset=0
        0x40, 0x06, 0x00, 0x00,  // TTL=64, Protocol=6 (TCP), Checksum=0 (will be calculated)
        0x0A, 0x08, 0x00, 0x02,  // Source IP (10.8.0.2)
        0x0A, 0x08, 0x00, 0x03,  // Dest IP (10.8.0.3)
        0x00, 0x50, 0x00, 0x80,  // TCP source port = 80, dest port = 128
        0x00, 0x00, 0x00, 0x00   // TCP sequence number
    };
    
    assert(vpn::IpHeader::is_valid_packet(valid_packet));
    std::cout << "✓ IP header validation works" << std::endl;
    
    // Test IP header parsing
    vpn::IpHeader header = vpn::IpHeader::parse(valid_packet);
    assert((header.version_ihl >> 4) == 4);
    assert((header.version_ihl & 0xF) == 5);
    std::cout << "✓ IP header parsing works" << std::endl;
    
    // Test stats
    auto stats = router.get_stats();
    std::cout << "✓ Router stats retrieved" << std::endl;
    
    std::cout << "✓ Packet Router tests passed" << std::endl;
}

// Test Configuration Manager
void test_config_manager() {
    std::cout << "Testing Configuration Manager..." << std::endl;
    
    vpn::ConfigManager config_mgr;
    
    // Test default configs
    auto server_config = vpn::ConfigManager::get_default_server_config();
    assert(server_config.listen_port == 1194);
    assert(server_config.server_ip == "10.8.0.1");
    std::cout << "✓ Default server config created" << std::endl;
    
    auto client_config = vpn::ConfigManager::get_default_client_config();
    assert(client_config.server_port == 1194);
    assert(client_config.auto_reconnect == true);
    std::cout << "✓ Default client config created" << std::endl;
    
    // Test validation
    std::string error_msg;
    bool valid = config_mgr.validate_server_config(server_config, error_msg);
    assert(valid);
    std::cout << "✓ Server config validation passed" << std::endl;
    
    valid = config_mgr.validate_client_config(client_config, error_msg);
    assert(valid);
    std::cout << "✓ Client config validation passed" << std::endl;
    
    // Test environment variable expansion
    std::string expanded = vpn::ConfigManager::expand_environment_variables("${USER}_test");
    std::cout << "✓ Environment variable expansion: " << expanded << std::endl;
    
    std::cout << "✓ Configuration Manager tests passed" << std::endl;
}

// Test crypto integration
void test_crypto_integration() {
    std::cout << "Testing Crypto Integration..." << std::endl;
    
    // This reuses the existing crypto test logic but in VPN context
    
    transport::SecureSession session1;
    transport::SecureSession session2;
    
    // Generate keypair for client
    crypto::KeyExchange kem;
    auto keypair = kem.generate_keypair();
    session1.set_client_keypair(keypair.first, keypair.second);
    
    // Server handles client public key
    std::vector<uint8_t> server_ct = session2.server_handle_public_key(keypair.first);
    
    // Client processes server response
    session1.client_process_server_hello(server_ct);
    
    // Both sessions should be authenticated
    assert(session1.is_authenticated());
    assert(session2.is_authenticated());
    std::cout << "✓ Key exchange successful" << std::endl;
    
    // Test packet encryption/decryption
    std::string test_data = "Hello VPN World!";
    std::vector<uint8_t> plaintext(test_data.begin(), test_data.end());
    
    std::vector<uint8_t> encrypted = session1.encrypt_packet(plaintext);
    std::vector<uint8_t> decrypted = session2.decrypt_packet(encrypted);
    
    assert(decrypted == plaintext);
    std::cout << "✓ Packet encryption/decryption successful" << std::endl;
    
    std::cout << "✓ Crypto Integration tests passed" << std::endl;
}

int main() {
    std::cout << "Running VPN Component Tests..." << std::endl;
    
    try {
        test_ip_pool();
        test_packet_router();
        test_config_manager();
        test_crypto_integration();
        test_tun_interface(); // Last because it might fail without root
        
        std::cout << "\n✅ All tests passed!" << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n❌ Test failed with unknown exception" << std::endl;
        return 1;
    }
}