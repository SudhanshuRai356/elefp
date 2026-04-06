#include "vpn/VpnServer.hpp"
#include "transport/TransportUtil.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstdio>
#include <cstdlib>

namespace {

std::string trim_copy(const std::string& input) {
    const auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    const auto last = input.find_last_not_of(" \t\r\n");
    return input.substr(first, last - first + 1);
}

std::string run_command_capture(const std::string& cmd) {
    std::array<char, 256> buffer{};
    std::string output;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return "";
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }

    pclose(pipe);
    return trim_copy(output);
}

bool run_quiet(const std::string& cmd) {
    std::string wrapped = cmd + " >/dev/null 2>&1";
    return std::system(wrapped.c_str()) == 0;
}

int netmask_to_prefix(const std::string& netmask) {
    in_addr mask_addr{};
    if (::inet_pton(AF_INET, netmask.c_str(), &mask_addr) != 1) {
        return -1;
    }

    const uint32_t mask = ntohl(mask_addr.s_addr);
    int prefix = 0;
    bool saw_zero = false;
    for (int bit = 31; bit >= 0; --bit) {
        const bool is_one = (mask & (1u << bit)) != 0;
        if (is_one) {
            if (saw_zero) {
                return -1;
            }
            ++prefix;
        } else {
            saw_zero = true;
        }
    }

    return prefix;
}

std::string build_network_cidr(const std::string& ip, const std::string& netmask) {
    in_addr ip_addr{};
    in_addr mask_addr{};
    if (::inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1 ||
        ::inet_pton(AF_INET, netmask.c_str(), &mask_addr) != 1) {
        return "";
    }

    const uint32_t ip_host = ntohl(ip_addr.s_addr);
    const uint32_t mask_host = ntohl(mask_addr.s_addr);
    const uint32_t network_host = ip_host & mask_host;

    in_addr network_addr{};
    network_addr.s_addr = htonl(network_host);

    char network_str[INET_ADDRSTRLEN] = {0};
    if (::inet_ntop(AF_INET, &network_addr, network_str, sizeof(network_str)) == nullptr) {
        return "";
    }

    const int prefix = netmask_to_prefix(netmask);
    if (prefix < 0) {
        return "";
    }

    return std::string(network_str) + "/" + std::to_string(prefix);
}

} // namespace

namespace vpn {

VpnServer::VpnServer(const Config& config) 
    : config_(config), running_(false), stop_threads_(false) {
    
    stats_.start_time = std::chrono::steady_clock::now();
    
    // Initialize components
    tun_interface_ = std::make_unique<TunInterface>();
    ip_pool_ = std::make_unique<IpPool>();
    packet_router_ = std::make_unique<PacketRouter>();
    io_context_ = std::make_unique<asio::io_context>();
}

VpnServer::~VpnServer() {
    stop();
}

bool VpnServer::start() {
    if (running_.load()) {
        return true; // Already running
    }
    
    std::cout << "Starting VPN Server..." << std::endl;
    
    // Initialize all components
    if (!initialize_tun_interface()) {
        std::cerr << "Failed to initialize TUN interface" << std::endl;
        return false;
    }
    
    if (!initialize_ip_pool()) {
        std::cerr << "Failed to initialize IP pool" << std::endl;
        return false;
    }
    
    if (!initialize_packet_router()) {
        std::cerr << "Failed to initialize packet router" << std::endl;
        return false;
    }
    
    if (!initialize_network_socket()) {
        std::cerr << "Failed to initialize network socket" << std::endl;
        return false;
    }

    if (config_.enable_internet_access && !setup_internet_access()) {
        std::cerr << "Failed to configure internet forwarding/NAT" << std::endl;
        return false;
    }
    
    running_.store(true);
    
    // Start threads
    start_worker_threads();
    start_packet_processing_threads();
    
    // Start async operations
    handle_udp_receive();
    handle_tun_packet();
    
    std::cout << "VPN Server started successfully" << std::endl;
    std::cout << "Listening on " << config_.listen_address 
              << ":" << config_.listen_port << std::endl;
    std::cout << "TUN interface: " << tun_interface_->get_interface_name() 
              << " (" << config_.server_ip << ")" << std::endl;
    
    return true;
}

void VpnServer::stop() {
    if (!running_.load()) {
        return;
    }
    
    std::cout << "Stopping VPN Server..." << std::endl;
    
    running_.store(false);
    stop_threads_.store(true);
    
    // Stop I/O operations
    if (udp_socket_) {
        udp_socket_->close();
    }
    
    if (io_context_) {
        io_context_->stop();
    }
    
    // Notify all waiting threads
    task_cv_.notify_all();
    
    // Join worker threads
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    // Join packet processing threads
    for (auto& thread : packet_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    cleanup_internet_access();
    
    // Clean up resources
    tun_interface_->close();
    
    std::cout << "VPN Server stopped" << std::endl;
}

bool VpnServer::initialize_tun_interface() {
    if (!tun_interface_->open(config_.tun_name)) {
        return false;
    }
    
    if (!tun_interface_->configure(config_.server_ip, config_.server_netmask, config_.tun_mtu)) {
        return false;
    }
    
    return true;
}

bool VpnServer::initialize_ip_pool() {
    return ip_pool_->add_range(config_.client_ip_range_start, 
                              config_.client_ip_range_end,
                              config_.server_netmask, 
                              config_.gateway);
}

bool VpnServer::initialize_packet_router() {
    // Add route for VPN network
    packet_router_->add_route("10.8.0.0", "255.255.255.0", 
                             config_.gateway, tun_interface_->get_interface_name(), 0);
    
    if (config_.enable_internet_access) {
        // Add default route for internet access
        packet_router_->add_route("0.0.0.0", "0.0.0.0", 
                                 config_.gateway, "eth0", 100);
    }
    
    return true;
}

bool VpnServer::initialize_network_socket() {
    try {
        asio::ip::udp::endpoint endpoint(
            asio::ip::make_address(config_.listen_address), 
            config_.listen_port);
        
        udp_socket_ = std::make_unique<asio::ip::udp::socket>(*io_context_, endpoint);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Socket initialization error: " << e.what() << std::endl;
        return false;
    }
}

bool VpnServer::setup_internet_access() {
    vpn_network_cidr_ = build_network_cidr(config_.server_ip, config_.server_netmask);
    if (vpn_network_cidr_.empty()) {
        std::cerr << "Unable to compute VPN network CIDR from server config" << std::endl;
        return false;
    }

    internet_interface_ = run_command_capture("ip -4 route show default | awk '{print $5; exit}'");
    if (internet_interface_.empty()) {
        std::cerr << "Unable to detect server default network interface" << std::endl;
        return false;
    }

    // Enable IPv4 forwarding.
    if (!run_quiet("sysctl -w net.ipv4.ip_forward=1")) {
        std::cerr << "Warning: failed to enable net.ipv4.ip_forward" << std::endl;
    }

    const std::string& tun_if = tun_interface_->get_interface_name();

    auto ensure_rule = [](const std::string& check_cmd, const std::string& add_cmd) -> bool {
        if (run_quiet(check_cmd)) {
            return true;
        }
        return run_quiet(add_cmd);
    };

    if (!ensure_rule(
            "iptables -C FORWARD -i " + tun_if + " -o " + internet_interface_ + " -j ACCEPT",
            "iptables -A FORWARD -i " + tun_if + " -o " + internet_interface_ + " -j ACCEPT")) {
        std::cerr << "Failed to add FORWARD rule for VPN -> internet" << std::endl;
        return false;
    }

    if (!ensure_rule(
            "iptables -C FORWARD -i " + internet_interface_ + " -o " + tun_if +
            " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A FORWARD -i " + internet_interface_ + " -o " + tun_if +
            " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")) {
        std::cerr << "Failed to add FORWARD rule for internet -> VPN" << std::endl;
        return false;
    }

    if (!ensure_rule(
            "iptables -t nat -C POSTROUTING -s " + vpn_network_cidr_ + " -o " + internet_interface_ +
            " -j MASQUERADE",
            "iptables -t nat -A POSTROUTING -s " + vpn_network_cidr_ + " -o " + internet_interface_ +
            " -j MASQUERADE")) {
        std::cerr << "Failed to add NAT MASQUERADE rule" << std::endl;
        return false;
    }

    internet_access_configured_ = true;
    std::cout << "Internet forwarding enabled via interface " << internet_interface_ << std::endl;
    return true;
}

void VpnServer::cleanup_internet_access() {
    if (!internet_access_configured_ || internet_interface_.empty() || vpn_network_cidr_.empty() || !tun_interface_) {
        return;
    }

    const std::string& tun_if = tun_interface_->get_interface_name();
    run_quiet("iptables -t nat -D POSTROUTING -s " + vpn_network_cidr_ + " -o " + internet_interface_ + " -j MASQUERADE");
    run_quiet("iptables -D FORWARD -i " + tun_if + " -o " + internet_interface_ + " -j ACCEPT");
    run_quiet("iptables -D FORWARD -i " + internet_interface_ + " -o " + tun_if +
              " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");

    internet_access_configured_ = false;
}

void VpnServer::start_worker_threads() {
    for (int i = 0; i < config_.worker_threads; ++i) {
        worker_threads_.emplace_back([this]() {
            while (running_.load()) {
                try {
                    io_context_->run();
                } catch (const std::exception& e) {
                    std::cerr << "Worker thread error: " << e.what() << std::endl;
                }
                
                if (running_.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    io_context_->restart();
                }
            }
        });
    }
}

void VpnServer::start_packet_processing_threads() {
    // Packet processing worker threads
    for (int i = 0; i < config_.worker_threads; ++i) {
        packet_threads_.emplace_back([this]() { packet_worker(); });
    }
    
    // Cleanup worker thread
    packet_threads_.emplace_back([this]() { cleanup_worker(); });
}

void VpnServer::handle_udp_receive() {
    if (!udp_socket_ || !running_.load()) return;
    
    auto buffer = std::make_shared<std::vector<uint8_t>>(8192);
    auto endpoint = std::make_shared<asio::ip::udp::endpoint>();
    
    udp_socket_->async_receive_from(
        asio::buffer(*buffer), *endpoint,
        [this, buffer, endpoint](const asio::error_code& error, std::size_t bytes_transferred) {
            if (!error && running_.load()) {
                buffer->resize(bytes_transferred);
                
                enqueue_task([this, buffer, endpoint]() {
                    handle_client_packet(*buffer, *endpoint);
                });
                
                stats_.packets_received.fetch_add(1);
                stats_.bytes_received.fetch_add(bytes_transferred);
                
                // Continue receiving
                handle_udp_receive();
            }
        });
}

void VpnServer::handle_tun_packet() {
    if (!tun_interface_->is_open() || !running_.load()) return;
    
    enqueue_task([this]() {
        std::vector<uint8_t> packet;
        ssize_t len = tun_interface_->read_packet(packet);
        
        if (len > 0 && running_.load()) {
            // Route packet based on destination
            std::string target_client;
            auto result = packet_router_->route_packet(packet, "", target_client);
            
            switch (result) {
                case PacketRouter::RouteResult::TO_CLIENT:
                    route_packet_to_client(packet, target_client);
                    break;
                case PacketRouter::RouteResult::TO_INTERNET:
                    route_packet_to_internet(packet);
                    break;
                default:
                    // Packet dropped
                    break;
            }
            
            // Continue reading TUN packets
            handle_tun_packet();
        }
    });
}

std::string VpnServer::generate_client_id(const asio::ip::udp::endpoint& endpoint) {
    std::ostringstream oss;
    oss << endpoint.address().to_string() << ":" << endpoint.port();
    return oss.str();
}

std::unique_ptr<VpnServer::ClientSession> VpnServer::create_client_session(
    const asio::ip::udp::endpoint& endpoint) {
    
    std::string client_id = generate_client_id(endpoint);
    auto session = std::make_unique<ClientSession>(client_id, endpoint);
    
    // Allocate IP address
    session->client_ip = ip_pool_->allocate_ip(client_id);
    if (session->client_ip.empty()) {
        return nullptr; // No available IPs
    }
    
    // Create secure session
    session->secure_session = session_manager_.create_session(
        std::hash<std::string>{}(client_id));
    
    // Add to packet router
    packet_router_->add_client(client_id, 
                              PacketRouter::ip_string_to_uint32(session->client_ip));
    
    return session;
}

void VpnServer::handle_client_packet(const std::vector<uint8_t>& data, 
                                    const asio::ip::udp::endpoint& endpoint) {
    if (data.empty()) return;
    
    std::string endpoint_str = generate_client_id(endpoint);
    
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    // Check message type
    uint8_t msg_type = data[0];
    
    if (msg_type == 0x01) {
        // Key exchange message
        process_key_exchange(data, endpoint);
    } else if (msg_type == 0x03) {
        // Client auth signature (Dilithium mutual auth)
        process_client_auth(data, endpoint);
    } else if (msg_type == 0x10) {
        // VPN packet
        process_vpn_packet(data, endpoint);
    }
}

void VpnServer::process_key_exchange(const std::vector<uint8_t>& data,
                                    const asio::ip::udp::endpoint& endpoint) {
    if (data.size() < 2) return;

    std::string client_id = generate_client_id(endpoint);

    // Check if client exists
    auto client_it = clients_.find(client_id);
    if (client_it == clients_.end()) {
        // Create new client session
        auto session = create_client_session(endpoint);
        if (!session) {
            std::cerr << "Failed to create session for " << client_id << std::endl;
            return;
        }
        client_it = clients_.emplace(client_id, std::move(session)).first;
        endpoint_to_client_[generate_client_id(endpoint)] = client_id;

        std::cout << "New client connected: " << client_id
                  << " assigned IP: " << client_it->second->client_ip << std::endl;
    }

    auto& client = *client_it->second;
    client.last_activity = std::chrono::steady_clock::now();

    try {
        // Client hello format: 0x01 | kyber_pk(800) | dilithium_pk(1312)
        const size_t KYBER_PK_SIZE = 800;
        const size_t DILI_PK_SIZE = 1312;
        size_t payload_size = data.size() - 1; // skip msg type

        if (payload_size == KYBER_PK_SIZE + DILI_PK_SIZE) {
            // Authenticated handshake path
            std::vector<uint8_t> client_pk(data.begin() + 1, data.begin() + 1 + KYBER_PK_SIZE);
            std::vector<uint8_t> client_dili_pk(data.begin() + 1 + KYBER_PK_SIZE, data.end());

            // Server authenticated handshake - returns packed: ct_len(4) | ct | server_dili_pk | signature
            std::vector<uint8_t> packed_response = client.secure_session->server_handle_public_key_authenticated(client_pk, client_dili_pk);

            // Send response: 0x02 | packed_response
            std::vector<uint8_t> response;
            response.push_back(0x02);
            response.insert(response.end(), packed_response.begin(), packed_response.end());

            udp_socket_->send_to(asio::buffer(response), endpoint);
            // Don't set authenticated yet - wait for client auth msg (0x03)
            stats_.packets_sent.fetch_add(1);
            stats_.bytes_sent.fetch_add(response.size());

            std::cout << "Authenticated key exchange phase 1 completed for " << client_id << std::endl;
        } else {
            // Fallback: unauthenticated handshake (backward compat for old tests)
            std::vector<uint8_t> client_pk(data.begin() + 1, data.end());
            std::vector<uint8_t> server_ct = client.secure_session->server_handle_public_key(client_pk);

            std::vector<uint8_t> response;
            response.push_back(0x02);
            response.insert(response.end(), server_ct.begin(), server_ct.end());

            udp_socket_->send_to(asio::buffer(response), endpoint);
            client.authenticated = true;
            stats_.packets_sent.fetch_add(1);
            stats_.bytes_sent.fetch_add(response.size());

            std::cout << "Key exchange completed for " << client_id << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Key exchange error for " << client_id << ": " << e.what() << std::endl;
        remove_client_session(client_id);
    }
}

void VpnServer::process_client_auth(const std::vector<uint8_t>& data,
                                    const asio::ip::udp::endpoint& endpoint) {
    // Client auth format: 0x03 | client_dilithium_pk(1312) | client_signature(variable)
    std::string client_id = generate_client_id(endpoint);

    auto client_it = clients_.find(client_id);
    if (client_it == clients_.end()) {
        std::cerr << "Client auth from unknown client: " << client_id << std::endl;
        return;
    }

    auto& client = *client_it->second;
    client.last_activity = std::chrono::steady_clock::now();

    try {
        const size_t DILI_PK_SIZE = 1312;
        if (data.size() < 1 + DILI_PK_SIZE + 1) {
            std::cerr << "Client auth message too short from " << client_id << std::endl;
            return;
        }

        std::vector<uint8_t> client_signature(data.begin() + 1 + DILI_PK_SIZE, data.end());

        if (client.secure_session->server_verify_client_signature(client_signature, {})) {
            client.authenticated = true;

            // Send client network configuration:
            // 0x04 | client_ip(4) | netmask(4) | gateway(4)
            std::vector<uint8_t> config_msg;
            config_msg.reserve(13);
            config_msg.push_back(0x04);

            auto append_ipv4 = [&config_msg](const std::string& ip_str) -> bool {
                in_addr addr{};
                if (::inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
                    return false;
                }
                const auto* raw = reinterpret_cast<const uint8_t*>(&addr.s_addr);
                config_msg.insert(config_msg.end(), raw, raw + 4);
                return true;
            };

            if (!append_ipv4(client.client_ip) ||
                !append_ipv4(config_.server_netmask) ||
                !append_ipv4(config_.gateway)) {
                std::cerr << "Failed to encode client network configuration for " << client_id << std::endl;
                remove_client_session(client_id);
                return;
            }

            udp_socket_->send_to(asio::buffer(config_msg), endpoint);
            stats_.packets_sent.fetch_add(1);
            stats_.bytes_sent.fetch_add(config_msg.size());

            std::cout << "Mutual authentication completed for " << client_id << std::endl;
        } else {
            std::cerr << "Client signature verification failed for " << client_id << std::endl;
            remove_client_session(client_id);
        }
    } catch (const std::exception& e) {
        std::cerr << "Client auth error for " << client_id << ": " << e.what() << std::endl;
        remove_client_session(client_id);
    }
}

void VpnServer::process_vpn_packet(const std::vector<uint8_t>& data, 
                                  const asio::ip::udp::endpoint& endpoint) {
    std::string client_id = generate_client_id(endpoint);
    
    auto client_it = clients_.find(client_id);
    if (client_it == clients_.end() || !client_it->second->authenticated) {
        return; // Unknown or unauthenticated client
    }
    
    auto& client = *client_it->second;
    client.last_activity = std::chrono::steady_clock::now();
    
    try {
        // Decrypt VPN packet
        std::vector<uint8_t> decrypted = client.secure_session->decrypt_packet(data);
        
        // Route the decrypted packet
        std::string target_client;
        auto result = packet_router_->route_packet(decrypted, client_id, target_client);
        
        switch (result) {
            case PacketRouter::RouteResult::TO_CLIENT:
                route_packet_to_client(decrypted, target_client);
                break;
            case PacketRouter::RouteResult::TO_INTERNET:
                route_packet_to_internet(decrypted);
                break;
            default:
                // Packet dropped
                break;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "VPN packet processing error for " << client_id << ": " << e.what() << std::endl;
    }
}

void VpnServer::route_packet_to_client(const std::vector<uint8_t>& packet, 
                                      const std::string& target_client) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    auto client_it = clients_.find(target_client);
    if (client_it == clients_.end() || !client_it->second->authenticated) {
        return;
    }
    
    auto& client = *client_it->second;
    
    try {
        // Encrypt packet
        std::vector<uint8_t> encrypted = client.secure_session->encrypt_packet(packet);
        
        // Send to client
        udp_socket_->send_to(asio::buffer(encrypted), client.endpoint);
        
        stats_.packets_sent.fetch_add(1);
        stats_.bytes_sent.fetch_add(encrypted.size());
        
    } catch (const std::exception& e) {
        std::cerr << "Failed to route packet to " << target_client << ": " << e.what() << std::endl;
    }
}

void VpnServer::route_packet_to_internet(std::vector<uint8_t>& packet) {
    // Write packet to TUN interface (it will be routed by the system)
    tun_interface_->write_packet(packet);
}

void VpnServer::cleanup_expired_sessions() {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(config_.session_timeout_seconds);
    
    auto it = clients_.begin();
    while (it != clients_.end()) {
        if (now - it->second->last_activity > timeout) {
            std::cout << "Session expired for " << it->first << std::endl;
            
            // Clean up resources
            ip_pool_->release_ip(it->first);
            packet_router_->remove_client(it->first);
            endpoint_to_client_.erase(generate_client_id(it->second->endpoint));
            
            it = clients_.erase(it);
        } else {
            ++it;
        }
    }
    
    stats_.active_clients.store(clients_.size());
}

void VpnServer::remove_client_session(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    auto it = clients_.find(client_id);
    if (it != clients_.end()) {
        ip_pool_->release_ip(client_id);
        packet_router_->remove_client(client_id);
        endpoint_to_client_.erase(generate_client_id(it->second->endpoint));
        clients_.erase(it);
        
        stats_.active_clients.store(clients_.size());
    }
}

void VpnServer::packet_worker() {
    while (!stop_threads_.load()) {
        std::unique_lock<std::mutex> lock(task_mutex_);
        
        task_cv_.wait(lock, [this]() {
            return !task_queue_.empty() || stop_threads_.load();
        });
        
        if (stop_threads_.load()) break;
        
        if (!task_queue_.empty()) {
            auto task = std::move(task_queue_.front());
            task_queue_.pop();
            lock.unlock();
            
            try {
                task();
            } catch (const std::exception& e) {
                std::cerr << "Task execution error: " << e.what() << std::endl;
            }
        }
    }
}

void VpnServer::cleanup_worker() {
    while (!stop_threads_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(30)); // Cleanup every 30 seconds
        
        if (!stop_threads_.load()) {
            cleanup_expired_sessions();
        }
    }
}

void VpnServer::enqueue_task(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(task_mutex_);
        task_queue_.push(std::move(task));
    }
    task_cv_.notify_one();
}

VpnServer::ServerStats VpnServer::get_stats() const {
    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.start_time);
    
    ServerStats stats;
    stats.packets_sent = stats_.packets_sent.load();
    stats.packets_received = stats_.packets_received.load();
    stats.bytes_sent = stats_.bytes_sent.load();
    stats.bytes_received = stats_.bytes_received.load();
    stats.active_clients = stats_.active_clients.load();
    stats.uptime_seconds = uptime.count();
    stats.routing_stats = packet_router_->get_stats();
    
    return stats;
}

std::vector<std::string> VpnServer::get_connected_clients() const {
    std::lock_guard<std::mutex> lock(clients_mutex_);
    
    std::vector<std::string> result;
    for (const auto& client : clients_) {
        if (client.second->authenticated) {
            result.push_back(client.first);
        }
    }
    
    return result;
}

size_t VpnServer::get_client_count() const {
    return stats_.active_clients.load();
}

std::string VpnServer::get_server_status() const {
    auto stats = get_stats();
    
    std::ostringstream oss;
    oss << "VPN Server Status:\n"
        << "  Running: " << (running_.load() ? "Yes" : "No") << "\n"
        << "  Uptime: " << stats.uptime_seconds << " seconds\n"
        << "  Active clients: " << stats.active_clients << "/" << config_.max_clients << "\n"
        << "  Packets sent: " << stats.packets_sent << "\n"
        << "  Packets received: " << stats.packets_received << "\n"
        << "  Bytes sent: " << stats.bytes_sent << "\n"
        << "  Bytes received: " << stats.bytes_received << "\n"
        << "  TUN interface: " << tun_interface_->get_interface_name() << " (" << config_.server_ip << ")\n"
        << "  Listen address: " << config_.listen_address << ":" << config_.listen_port;
    
    return oss.str();
}

} // namespace vpn