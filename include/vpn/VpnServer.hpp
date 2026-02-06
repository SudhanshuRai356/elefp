#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <unordered_map>
#include <asio.hpp>

#include "vpn/TunInterface.hpp"
#include "vpn/IpPool.hpp"
#include "vpn/PacketRouter.hpp"
#include "transport/SessionManager.hpp"
#include "transport/SecureSession.hpp"

namespace vpn {

class VpnServer {
public:
    struct Config {
        std::string listen_address;
        uint16_t listen_port;
        std::string tun_name;
        std::string server_ip;
        std::string server_netmask;
        std::string client_ip_range_start;
        std::string client_ip_range_end;
        std::string gateway;
        int max_clients;
        int worker_threads;
        int tun_mtu;
        bool enable_internet_access;
        std::vector<std::string> dns_servers;
        uint32_t session_timeout_seconds;
        
        // Constructor with defaults
        Config() 
            : listen_address("0.0.0.0")
            , listen_port(1194)
            , tun_name("")
            , server_ip("10.8.0.1")
            , server_netmask("255.255.255.0")
            , client_ip_range_start("10.8.0.10")
            , client_ip_range_end("10.8.0.100")
            , gateway("10.8.0.1")
            , max_clients(50)
            , worker_threads(4)
            , tun_mtu(1500)
            , enable_internet_access(true)
            , dns_servers({"8.8.8.8", "8.8.4.4"})
            , session_timeout_seconds(300)
        {}
    };
    
    struct ClientSession {
        std::string client_id;
        std::string client_ip;
        std::shared_ptr<transport::SecureSession> secure_session;
        asio::ip::udp::endpoint endpoint;
        std::chrono::steady_clock::time_point last_activity;
        bool authenticated = false;
        
        ClientSession(const std::string& id, const asio::ip::udp::endpoint& ep)
            : client_id(id), endpoint(ep), last_activity(std::chrono::steady_clock::now()) {}
    };

private:
    Config config_;
    std::atomic<bool> running_;
    
    // Networking
    std::unique_ptr<asio::io_context> io_context_;
    std::unique_ptr<asio::ip::udp::socket> udp_socket_;
    std::vector<std::thread> worker_threads_;
    
    // VPN components
    std::unique_ptr<TunInterface> tun_interface_;
    std::unique_ptr<IpPool> ip_pool_;
    std::unique_ptr<PacketRouter> packet_router_;
    transport::SessionManager session_manager_;
    
    // Client management
    std::unordered_map<std::string, std::unique_ptr<ClientSession>> clients_;
    std::unordered_map<std::string, std::string> endpoint_to_client_; // endpoint_string -> client_id
    mutable std::mutex clients_mutex_;
    
    // Thread pool for packet processing
    std::vector<std::thread> packet_threads_;
    std::queue<std::function<void()>> task_queue_;
    std::mutex task_mutex_;
    std::condition_variable task_cv_;
    std::atomic<bool> stop_threads_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> packets_sent{0};
        std::atomic<uint64_t> packets_received{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
        std::atomic<uint32_t> active_clients{0};
        std::chrono::steady_clock::time_point start_time;
    } stats_;
    
    // Initialization
    bool initialize_tun_interface();
    bool initialize_ip_pool();
    bool initialize_packet_router();
    bool initialize_network_socket();
    void start_worker_threads();
    void start_packet_processing_threads();
    
    // Network handling
    void handle_udp_receive();
    void handle_client_packet(const std::vector<uint8_t>& data, 
                             const asio::ip::udp::endpoint& endpoint);
    void handle_tun_packet();
    
    // Client management
    std::string generate_client_id(const asio::ip::udp::endpoint& endpoint);
    std::unique_ptr<ClientSession> create_client_session(const asio::ip::udp::endpoint& endpoint);
    void cleanup_expired_sessions();
    void remove_client_session(const std::string& client_id);
    
    // Packet processing
    void process_key_exchange(const std::vector<uint8_t>& data, 
                             const asio::ip::udp::endpoint& endpoint);
    void process_vpn_packet(const std::vector<uint8_t>& data, 
                           const asio::ip::udp::endpoint& endpoint);
    
    void route_packet_to_client(const std::vector<uint8_t>& packet, 
                               const std::string& target_client);
    void route_packet_to_internet(std::vector<uint8_t>& packet);
    
    // Worker thread functions
    void packet_worker();
    void cleanup_worker();
    
    // Task queue management
    void enqueue_task(std::function<void()> task);
    
public:
    explicit VpnServer(const Config& config = Config{});
    ~VpnServer();
    
    // Non-copyable, non-movable
    VpnServer(const VpnServer&) = delete;
    VpnServer& operator=(const VpnServer&) = delete;
    VpnServer(VpnServer&&) = delete;
    VpnServer& operator=(VpnServer&&) = delete;
    
    // Server lifecycle
    bool start();
    void stop();
    bool is_running() const { return running_.load(); }
    
    // Configuration
    const Config& get_config() const { return config_; }
    void update_config(const Config& config);
    
    // Client information
    std::vector<std::string> get_connected_clients() const;
    size_t get_client_count() const;
    bool is_client_connected(const std::string& client_id) const;
    
    // Statistics
    struct ServerStats {
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint32_t active_clients;
        uint64_t uptime_seconds;
        PacketRouter::Stats routing_stats;
    };
    
    ServerStats get_stats() const;
    void reset_stats();
    
    // Administrative functions
    bool disconnect_client(const std::string& client_id);
    std::vector<std::string> get_client_ips() const;
    std::string get_server_status() const;
};

} // namespace vpn