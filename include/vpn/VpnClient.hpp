#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <memory>
#include <mutex>
#include <asio.hpp>
#include <chrono>

#include "vpn/TunInterface.hpp"
#include "transport/SecureSession.hpp"
#include "crypto/KeyExchange.hpp"

namespace vpn {

class VpnClient {
public:
    struct Config {
        std::string server_address;
        uint16_t server_port;
        std::string tun_name;
        int tun_mtu;
        uint32_t connect_timeout_seconds;
        uint32_t keepalive_interval_seconds;
        uint32_t reconnect_delay_seconds;
        uint32_t max_reconnect_attempts;
        bool auto_reconnect;
        std::vector<std::string> dns_servers;
        std::vector<std::string> routes; // Additional routes to add
        bool redirect_gateway; // Route all traffic through VPN
        
        // Constructor with defaults
        Config() 
            : server_address("127.0.0.1")
            , server_port(1194)
            , tun_name("")
            , tun_mtu(1500)
            , connect_timeout_seconds(30)
            , keepalive_interval_seconds(60)
            , reconnect_delay_seconds(5)
            , max_reconnect_attempts(10)
            , auto_reconnect(true)
            , dns_servers({"8.8.8.8", "8.8.4.4"})
            , routes()
            , redirect_gateway(true)
        {}
    };
    
    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        AUTHENTICATING,
        CONNECTED,
        RECONNECTING,
        ERROR
    };

private:
    Config config_;
    std::atomic<bool> running_;
    std::atomic<ConnectionState> connection_state_;
    
    // Networking
    std::unique_ptr<asio::io_context> io_context_;
    std::unique_ptr<asio::ip::udp::socket> udp_socket_;
    asio::ip::udp::endpoint server_endpoint_;
    std::thread network_thread_;
    
    // VPN components
    std::unique_ptr<TunInterface> tun_interface_;
    transport::SecureSession secure_session_;
    
    // Connection management
    std::string assigned_ip_;
    std::string assigned_netmask_;
    std::string gateway_ip_;
    std::vector<std::string> original_routes_; // Backup of original routes
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> packets_sent{0};
        std::atomic<uint64_t> packets_received{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
        std::atomic<uint64_t> connection_attempts{0};
        std::atomic<uint64_t> reconnections{0};
        std::chrono::steady_clock::time_point connection_start_time;
    } stats_;
    
    // Error handling
    std::string last_error_;
    mutable std::mutex error_mutex_;
    
    // Connection management
    bool initialize_networking();
    bool initialize_tun_interface();
    bool perform_key_exchange();
    bool configure_routes();
    void cleanup_routes();
    
    // Network operations
    void network_worker();
    void handle_udp_receive();
    void handle_tun_receive();
    void send_keepalive();
    
    // Packet processing
    void process_server_packet(const std::vector<uint8_t>& data);
    void process_tun_packet(const std::vector<uint8_t>& packet);
    
    // Connection lifecycle
    bool attempt_connection();
    void handle_disconnection();
    void attempt_reconnection();
    
    // Utility functions
    void set_connection_state(ConnectionState state);
    void set_error(const std::string& error);
    bool is_expected_server_sender(const asio::ip::udp::endpoint& sender) const;
    bool wait_for_server_response(uint8_t expected_type, std::vector<uint8_t>& response, 
                                  uint32_t timeout_seconds = 10);
    
public:
    explicit VpnClient(const Config& config = Config{});
    ~VpnClient();
    
    // Non-copyable, non-movable
    VpnClient(const VpnClient&) = delete;
    VpnClient& operator=(const VpnClient&) = delete;
    VpnClient(VpnClient&&) = delete;
    VpnClient& operator=(VpnClient&&) = delete;
    
    // Connection management
    bool connect();
    void disconnect();
    bool is_connected() const;
    ConnectionState get_connection_state() const { return connection_state_.load(); }
    
    // Configuration
    const Config& get_config() const { return config_; }
    void update_config(const Config& config);
    
    // Connection information
    std::string get_assigned_ip() const { return assigned_ip_; }
    std::string get_gateway_ip() const { return gateway_ip_; }
    std::string get_tun_interface_name() const;
    
    // Error information
    std::string get_last_error() const;
    
    // Statistics
    struct ClientStats {
        uint64_t packets_sent;
        uint64_t packets_received;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint64_t connection_attempts;
        uint64_t reconnections;
        uint64_t connection_duration_seconds;
        ConnectionState state;
    };
    
    ClientStats get_stats() const;
    void reset_stats();
    
    // Status and monitoring
    std::string get_connection_status() const;
    bool test_connectivity(const std::string& target = "8.8.8.8") const;
    
    // Route management
    static bool add_system_route(const std::string& dest, const std::string& gateway, 
                                const std::string& interface = "");
    static bool delete_system_route(const std::string& dest, const std::string& gateway, 
                                   const std::string& interface = "");
    static std::vector<std::string> get_system_routes();
    static bool backup_routes();
    static bool restore_routes();
};

} // namespace vpn