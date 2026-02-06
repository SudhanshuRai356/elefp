#include "vpn/VpnClient.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>

namespace vpn {

VpnClient::VpnClient(const Config& config) 
    : config_(config), running_(false), connection_state_(ConnectionState::DISCONNECTED) {
    
    tun_interface_ = std::make_unique<TunInterface>();
    io_context_ = std::make_unique<asio::io_context>();
}

VpnClient::~VpnClient() {
    disconnect();
}

bool VpnClient::connect() {
    if (connection_state_.load() != ConnectionState::DISCONNECTED) {
        return false; // Already connecting or connected
    }
    
    std::cout << "Connecting to VPN server " << config_.server_address 
              << ":" << config_.server_port << std::endl;
    
    set_connection_state(ConnectionState::CONNECTING);
    stats_.connection_attempts.fetch_add(1);
    
    if (!initialize_networking()) {
        set_error("Failed to initialize networking");
        set_connection_state(ConnectionState::ERROR);
        return false;
    }
    
    if (!initialize_tun_interface()) {
        set_error("Failed to initialize TUN interface");
        set_connection_state(ConnectionState::ERROR);
        return false;
    }
    
    if (!attempt_connection()) {
        set_connection_state(ConnectionState::ERROR);
        return false;
    }
    
    running_.store(true);
    set_connection_state(ConnectionState::CONNECTED);
    stats_.connection_start_time = std::chrono::steady_clock::now();
    
    // Start network worker thread
    network_thread_ = std::thread([this]() { network_worker(); });
    
    std::cout << "Connected to VPN server successfully" << std::endl;
    std::cout << "TUN interface: " << get_tun_interface_name() << std::endl;
    std::cout << "Assigned IP: " << assigned_ip_ << std::endl;
    
    return true;
}

void VpnClient::disconnect() {
    if (connection_state_.load() == ConnectionState::DISCONNECTED) {
        return;
    }
    
    std::cout << "Disconnecting from VPN server..." << std::endl;
    
    running_.store(false);
    set_connection_state(ConnectionState::DISCONNECTED);
    
    // Stop I/O operations
    if (udp_socket_) {
        udp_socket_->close();
    }
    
    if (io_context_) {
        io_context_->stop();
    }
    
    // Join network thread
    if (network_thread_.joinable()) {
        network_thread_.join();
    }
    
    // Cleanup routes
    cleanup_routes();
    
    // Close TUN interface
    if (tun_interface_) {
        tun_interface_->close();
    }
    
    std::cout << "Disconnected from VPN server" << std::endl;
}

bool VpnClient::is_connected() const {
    return connection_state_.load() == ConnectionState::CONNECTED;
}

bool VpnClient::initialize_networking() {
    try {
        server_endpoint_ = asio::ip::udp::endpoint(
            asio::ip::make_address(config_.server_address), 
            config_.server_port);
        
        udp_socket_ = std::make_unique<asio::ip::udp::socket>(*io_context_);
        udp_socket_->open(asio::ip::udp::v4());
        
        return true;
    } catch (const std::exception& e) {
        set_error("Networking initialization failed: " + std::string(e.what()));
        return false;
    }
}

bool VpnClient::initialize_tun_interface() {
    if (!tun_interface_->open(config_.tun_name)) {
        set_error("Failed to create TUN interface");
        return false;
    }
    
    return true;
}

bool VpnClient::attempt_connection() {
    try {
        set_connection_state(ConnectionState::AUTHENTICATING);
        
        // Generate keypair
        auto keypair = key_exchange_.generate_keypair();
        secure_session_.set_client_keypair(keypair.first, keypair.second);
        
        // Send client hello (public key)
        std::vector<uint8_t> hello_msg;
        hello_msg.push_back(0x01); // Key exchange message type
        hello_msg.insert(hello_msg.end(), keypair.first.begin(), keypair.first.end());
        
        udp_socket_->send_to(asio::buffer(hello_msg), server_endpoint_);
        stats_.packets_sent.fetch_add(1);
        stats_.bytes_sent.fetch_add(hello_msg.size());
        
        // Wait for server response
        std::vector<uint8_t> server_response;
        if (!wait_for_server_response(0x02, server_response, config_.connect_timeout_seconds)) {
            set_error("Server hello timeout");
            return false;
        }
        
        // Process server hello (extract ciphertext)
        std::vector<uint8_t> server_ct(server_response.begin() + 1, server_response.end());
        secure_session_.client_process_server_hello(server_ct);
        
        std::cout << "Key exchange completed successfully" << std::endl;
        
        // For now, assign a static IP configuration
        // In a real implementation, this would come from the server
        assigned_ip_ = "10.8.0.2";
        assigned_netmask_ = "255.255.255.0";
        gateway_ip_ = "10.8.0.1";
        
        // Configure TUN interface
        if (!tun_interface_->configure(assigned_ip_, assigned_netmask_, config_.tun_mtu)) {
            set_error("Failed to configure TUN interface");
            return false;
        }
        
        // Configure routes
        if (!configure_routes()) {
            set_error("Failed to configure routes");
            return false;
        }
        
        return true;
        
    } catch (const std::exception& e) {
        set_error("Connection attempt failed: " + std::string(e.what()));
        return false;
    }
}

bool VpnClient::configure_routes() {
    if (config_.redirect_gateway) {
        // Add route for VPN server (before default route change)
        std::string server_route_cmd = "ip route add " + config_.server_address + 
                                      " via $(ip route | grep default | awk '{print $3}' | head -1)";
        if (system(server_route_cmd.c_str()) != 0) {
            std::cerr << "Warning: Failed to add server route" << std::endl;
        }
        
        // Add default route through VPN
        std::string default_route_cmd = "ip route add default via " + gateway_ip_ + 
                                       " dev " + tun_interface_->get_interface_name() + 
                                       " metric 1";
        if (system(default_route_cmd.c_str()) != 0) {
            set_error("Failed to add default route through VPN");
            return false;
        }
    }
    
    // Add custom routes
    for (const auto& route : config_.routes) {
        std::string route_cmd = "ip route add " + route + " via " + gateway_ip_ + 
                               " dev " + tun_interface_->get_interface_name();
        if (system(route_cmd.c_str()) != 0) {
            std::cerr << "Warning: Failed to add custom route: " << route << std::endl;
        }
    }
    
    return true;
}

void VpnClient::cleanup_routes() {
    if (config_.redirect_gateway) {
        // Remove default route through VPN
        std::string default_route_cmd = "ip route del default via " + gateway_ip_ + 
                                       " dev " + get_tun_interface_name() + " 2>/dev/null";
        system(default_route_cmd.c_str());
        
        // Remove server route
        std::string server_route_cmd = "ip route del " + config_.server_address + " 2>/dev/null";
        system(server_route_cmd.c_str());
    }
    
    // Remove custom routes
    for (const auto& route : config_.routes) {
        std::string route_cmd = "ip route del " + route + " 2>/dev/null";
        system(route_cmd.c_str());
    }
}

void VpnClient::network_worker() {
    while (running_.load()) {
        try {
            // Handle UDP and TUN packets
            handle_udp_receive();
            handle_tun_receive();
            
            // Run I/O operations
            io_context_->poll();
            
            // Send keepalive periodically
            static auto last_keepalive = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_keepalive).count() 
                >= config_.keepalive_interval_seconds) {
                send_keepalive();
                last_keepalive = now;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
        } catch (const std::exception& e) {
            std::cerr << "Network worker error: " << e.what() << std::endl;
            
            if (running_.load() && config_.auto_reconnect) {
                handle_disconnection();
                attempt_reconnection();
            }
        }
    }
}

void VpnClient::handle_udp_receive() {
    if (!udp_socket_ || !running_.load()) return;
    
    try {
        std::vector<uint8_t> buffer(8192);
        asio::ip::udp::endpoint sender_endpoint;
        
        asio::error_code error;
        std::size_t len = udp_socket_->receive_from(
            asio::buffer(buffer), sender_endpoint, 0, error);
        
        if (!error && len > 0 && sender_endpoint == server_endpoint_) {
            buffer.resize(len);
            process_server_packet(buffer);
            
            stats_.packets_received.fetch_add(1);
            stats_.bytes_received.fetch_add(len);
        }
    } catch (const std::exception&) {
        // Non-blocking receive, errors are expected
    }
}

void VpnClient::handle_tun_receive() {
    if (!tun_interface_->is_open() || !running_.load()) return;
    
    try {
        std::vector<uint8_t> packet;
        ssize_t len = tun_interface_->read_packet(packet);
        
        if (len > 0) {
            process_tun_packet(packet);
        }
    } catch (const std::exception&) {
        // Non-blocking read, errors are expected
    }
}

void VpnClient::process_server_packet(const std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    try {
        uint8_t msg_type = data[0];
        
        if (msg_type == 0x10) {
            // Encrypted VPN packet
            std::vector<uint8_t> decrypted = secure_session_.decrypt_packet(data);
            
            // Write decrypted packet to TUN interface
            tun_interface_->write_packet(decrypted);
        }
        // Other message types can be handled here
        
    } catch (const std::exception& e) {
        std::cerr << "Server packet processing error: " << e.what() << std::endl;
    }
}

void VpnClient::process_tun_packet(const std::vector<uint8_t>& packet) {
    try {
        // Encrypt packet and send to server
        std::vector<uint8_t> encrypted = secure_session_.encrypt_packet(packet);
        
        udp_socket_->send_to(asio::buffer(encrypted), server_endpoint_);
        
        stats_.packets_sent.fetch_add(1);
        stats_.bytes_sent.fetch_add(encrypted.size());
        
    } catch (const std::exception& e) {
        std::cerr << "TUN packet processing error: " << e.what() << std::endl;
    }
}

void VpnClient::send_keepalive() {
    try {
        // Send a small encrypted packet as keepalive
        std::vector<uint8_t> keepalive_data = {0x00}; // Minimal payload
        std::vector<uint8_t> encrypted = secure_session_.encrypt_packet(keepalive_data);
        
        udp_socket_->send_to(asio::buffer(encrypted), server_endpoint_);
        
    } catch (const std::exception&) {
        // Keepalive errors are not critical
    }
}

bool VpnClient::wait_for_server_response(uint8_t expected_type, std::vector<uint8_t>& response, 
                                        uint32_t timeout_seconds) {
    auto start_time = std::chrono::steady_clock::now();
    auto timeout_duration = std::chrono::seconds(timeout_seconds);
    
    while (std::chrono::steady_clock::now() - start_time < timeout_duration) {
        try {
            std::vector<uint8_t> buffer(8192);
            asio::ip::udp::endpoint sender_endpoint;
            
            asio::error_code error;
            std::size_t len = udp_socket_->receive_from(
                asio::buffer(buffer), sender_endpoint, 0, error);
            
            if (!error && len > 0 && sender_endpoint == server_endpoint_) {
                buffer.resize(len);
                
                if (!buffer.empty() && buffer[0] == expected_type) {
                    response = std::move(buffer);
                    stats_.packets_received.fetch_add(1);
                    stats_.bytes_received.fetch_add(len);
                    return true;
                }
            }
        } catch (const std::exception&) {
            // Continue waiting
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return false; // Timeout
}

void VpnClient::handle_disconnection() {
    if (connection_state_.load() == ConnectionState::DISCONNECTED) return;
    
    std::cout << "Connection lost, handling disconnection..." << std::endl;
    set_connection_state(ConnectionState::DISCONNECTED);
    
    cleanup_routes();
}

void VpnClient::attempt_reconnection() {
    if (!config_.auto_reconnect) return;
    
    set_connection_state(ConnectionState::RECONNECTING);
    
    for (uint32_t attempt = 1; attempt <= config_.max_reconnect_attempts; ++attempt) {
        std::cout << "Reconnection attempt " << attempt << "/" 
                  << config_.max_reconnect_attempts << std::endl;
        
        std::this_thread::sleep_for(std::chrono::seconds(config_.reconnect_delay_seconds));
        
        if (attempt_connection()) {
            set_connection_state(ConnectionState::CONNECTED);
            stats_.reconnections.fetch_add(1);
            stats_.connection_start_time = std::chrono::steady_clock::now();
            
            std::cout << "Reconnection successful" << std::endl;
            return;
        }
    }
    
    set_error("Failed to reconnect after " + std::to_string(config_.max_reconnect_attempts) + 
              " attempts");
    set_connection_state(ConnectionState::ERROR);
}

void VpnClient::set_connection_state(ConnectionState state) {
    connection_state_.store(state);
}

void VpnClient::set_error(const std::string& error) {
    std::lock_guard<std::mutex> lock(error_mutex_);
    last_error_ = error;
    std::cerr << "VPN Client Error: " << error << std::endl;
}

std::string VpnClient::get_last_error() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    return last_error_;
}

std::string VpnClient::get_tun_interface_name() const {
    return tun_interface_ ? tun_interface_->get_interface_name() : "";
}

VpnClient::ClientStats VpnClient::get_stats() const {
    auto now = std::chrono::steady_clock::now();
    auto connection_duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats_.connection_start_time);
    
    ClientStats stats;
    stats.packets_sent = stats_.packets_sent.load();
    stats.packets_received = stats_.packets_received.load();
    stats.bytes_sent = stats_.bytes_sent.load();
    stats.bytes_received = stats_.bytes_received.load();
    stats.connection_attempts = stats_.connection_attempts.load();
    stats.reconnections = stats_.reconnections.load();
    stats.connection_duration_seconds = is_connected() ? connection_duration.count() : 0;
    stats.state = connection_state_.load();
    
    return stats;
}

std::string VpnClient::get_connection_status() const {
    auto stats = get_stats();
    
    std::ostringstream oss;
    oss << "VPN Client Status:\n"
        << "  State: ";
    
    switch (stats.state) {
        case ConnectionState::DISCONNECTED: oss << "Disconnected"; break;
        case ConnectionState::CONNECTING: oss << "Connecting"; break;
        case ConnectionState::AUTHENTICATING: oss << "Authenticating"; break;
        case ConnectionState::CONNECTED: oss << "Connected"; break;
        case ConnectionState::RECONNECTING: oss << "Reconnecting"; break;
        case ConnectionState::ERROR: oss << "Error"; break;
    }
    
    oss << "\n"
        << "  Server: " << config_.server_address << ":" << config_.server_port << "\n"
        << "  TUN interface: " << get_tun_interface_name() << "\n"
        << "  Assigned IP: " << assigned_ip_ << "\n"
        << "  Connection duration: " << stats.connection_duration_seconds << " seconds\n"
        << "  Packets sent: " << stats.packets_sent << "\n"
        << "  Packets received: " << stats.packets_received << "\n"
        << "  Bytes sent: " << stats.bytes_sent << "\n"
        << "  Bytes received: " << stats.bytes_received << "\n"
        << "  Connection attempts: " << stats.connection_attempts << "\n"
        << "  Reconnections: " << stats.reconnections;
    
    return oss.str();
}

bool VpnClient::test_connectivity(const std::string& target) const {
    if (!is_connected()) return false;
    
    std::string ping_cmd = "ping -c 1 -W 3 " + target + " > /dev/null 2>&1";
    return system(ping_cmd.c_str()) == 0;
}

} // namespace vpn