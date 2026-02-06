#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fstream>
#include <sstream>
#include <cstdint> // Added this include

namespace vpn {

class ConfigManager {
public:
    struct ServerConfig {
        // Network settings
        std::string listen_address = "0.0.0.0";
        uint16_t listen_port = 1194;
        std::string tun_name = "";
        std::string server_ip = "10.8.0.1";
        std::string server_netmask = "255.255.255.0";
        std::string client_ip_range_start = "10.8.0.10";
        std::string client_ip_range_end = "10.8.0.100";
        std::string gateway = "10.8.0.1";
        
        // Performance settings
        int max_clients = 50;
        int worker_threads = 4;
        int tun_mtu = 1500;
        uint32_t session_timeout_seconds = 300;
        
        // Features
        bool enable_internet_access = true;
        std::vector<std::string> dns_servers = {"8.8.8.8", "8.8.4.4"};
        
        // Logging
        std::string log_level = "info";
        std::string log_file = "";
        bool log_to_console = true;
        
        // Security
        uint32_t keepalive_interval = 60;
        uint32_t connection_timeout = 120;
    };
    
    struct ClientConfig {
        // Connection settings
        std::string server_address = "127.0.0.1";
        uint16_t server_port = 1194;
        std::string tun_name = "";
        int tun_mtu = 1500;
        
        // Timeouts and reconnection
        uint32_t connect_timeout_seconds = 30;
        uint32_t keepalive_interval_seconds = 60;
        uint32_t reconnect_delay_seconds = 5;
        uint32_t max_reconnect_attempts = 10;
        bool auto_reconnect = true;
        
        // Routing
        bool redirect_gateway = true;
        std::vector<std::string> routes;
        std::vector<std::string> dns_servers = {"8.8.8.8", "8.8.4.4"};
        
        // Logging
        std::string log_level = "info";
        std::string log_file = "";
        bool log_to_console = true;
    };

private:
    std::map<std::string, std::string> values;        // config key-value pairs
    std::string config_file;                          // path to current config file
    
    // Parsing helpers
    bool parse_config_file(const std::string& file_path);
    std::string get_string_value(const std::string& key, const std::string& default_value = "") const;
    int get_int_value(const std::string& key, int default_value = 0) const;
    bool get_bool_value(const std::string& key, bool default_value = false) const;
    uint16_t get_uint16_value(const std::string& key, uint16_t default_value = 0) const;
    uint32_t get_uint32_value(const std::string& key, uint32_t default_value = 0) const;
    std::vector<std::string> get_string_list_value(const std::string& key) const;
    
    // Validation
    bool validate_ip_address(const std::string& ip) const;
    bool validate_port(uint16_t port) const;
    bool validate_cidr(const std::string& cidr) const;
    
    void set_default_server_values();
    void set_default_client_values();
    
public:
    ConfigManager();
    ~ConfigManager() = default;
    
    // Configuration loading
    bool load_server_config(const std::string& file_path, ServerConfig& config);
    bool load_client_config(const std::string& file_path, ClientConfig& config);
    
    // Configuration saving
    bool save_server_config(const std::string& file_path, const ServerConfig& config);
    bool save_client_config(const std::string& file_path, const ClientConfig& config);
    
    // Generate default configurations
    static ServerConfig get_default_server_config();
    static ClientConfig get_default_client_config();
    
    // Configuration validation
    bool validate_server_config(const ServerConfig& config, std::string& error_message) const;
    bool validate_client_config(const ClientConfig& config, std::string& error_message) const;
    
    // Utility functions
    static bool create_config_directory(const std::string& path);
    static std::string get_default_config_dir();
    static std::string get_default_server_config_path();
    static std::string get_default_client_config_path();
    
    // Environment variable support  
    static std::string expand_environment_variables(const std::string& str);
    
    // Command line argument parsing
    static bool parse_server_args(int argc, char* argv[], ServerConfig& config, std::string& config_file);
    static bool parse_client_args(int argc, char* argv[], ClientConfig& config, std::string& config_file);
    
    // Help text
    static std::string get_server_help_text();
    static std::string get_client_help_text();
};

} // namespace vpn