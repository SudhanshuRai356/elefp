#include "vpn/VpnClient.hpp"
#include "vpn/ConfigManager.hpp"
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <thread>
#include <chrono>

std::unique_ptr<vpn::VpnClient> g_client;

void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", disconnecting..." << std::endl;
    if (g_client) {
        g_client->disconnect();
    }
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config FILE      Configuration file path" << std::endl;
    std::cout << "  -s, --server ADDRESS   Server address (default: 127.0.0.1)" << std::endl;
    std::cout << "  -p, --port PORT        Server port (default: 1194)" << std::endl;
    std::cout << "  -i, --interface NAME   TUN interface name" << std::endl;
    std::cout << "  -r, --no-redirect      Don't redirect default gateway" << std::endl;
    std::cout << "  -a, --auto-reconnect   Enable auto-reconnection" << std::endl;
    std::cout << "  -t, --timeout SECONDS  Connection timeout (default: 30)" << std::endl;
    std::cout << "  -d, --daemon           Run as daemon (background)" << std::endl;
    std::cout << "  -v, --verbose          Verbose output" << std::endl;
    std::cout << "  -h, --help             Show this help" << std::endl;
    std::cout << "  --generate-config      Generate default configuration file" << std::endl;
    std::cout << "  --status               Show connection status and exit" << std::endl;
    std::cout << "  --test-connectivity    Test connectivity and exit" << std::endl;
}

int main(int argc, char* argv[]) {
    vpn::VpnClient::Config config;
    vpn::ConfigManager config_mgr;
    std::string config_file = "";
    bool daemon_mode = false;
    bool verbose = false;
    bool generate_config = false;
    bool show_status = false;
    bool test_connectivity = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--generate-config") {
            generate_config = true;
        } else if (arg == "--status") {
            show_status = true;
        } else if (arg == "--test-connectivity") {
            test_connectivity = true;
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a file path" << std::endl;
                return 1;
            }
        } else if (arg == "-s" || arg == "--server") {
            if (i + 1 < argc) {
                config.server_address = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a server address" << std::endl;
                return 1;
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                config.server_port = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: " << arg << " requires a port number" << std::endl;
                return 1;
            }
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                config.tun_name = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an interface name" << std::endl;
                return 1;
            }
        } else if (arg == "-r" || arg == "--no-redirect") {
            config.redirect_gateway = false;
        } else if (arg == "-a" || arg == "--auto-reconnect") {
            config.auto_reconnect = true;
        } else if (arg == "-t" || arg == "--timeout") {
            if (i + 1 < argc) {
                config.connect_timeout_seconds = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: " << arg << " requires a timeout value" << std::endl;
                return 1;
            }
        } else if (arg == "-d" || arg == "--daemon") {
            daemon_mode = true;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else {
            std::cerr << "Error: Unknown option " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Generate default configuration if requested
    if (generate_config) {
        std::string default_config_path = vpn::ConfigManager::get_default_client_config_path();
        
        // Create config directory if it doesn't exist
        size_t last_slash = default_config_path.find_last_of('/');
        if (last_slash != std::string::npos) {
            std::string config_dir = default_config_path.substr(0, last_slash);
            vpn::ConfigManager::create_config_directory(config_dir);
        }
        
        // Convert to ConfigManager::ClientConfig for saving
        vpn::ConfigManager::ClientConfig save_config;
        save_config.server_address = config.server_address;
        save_config.server_port = config.server_port;
        save_config.tun_name = config.tun_name;
        save_config.tun_mtu = config.tun_mtu;
        save_config.connect_timeout_seconds = config.connect_timeout_seconds;
        save_config.keepalive_interval_seconds = config.keepalive_interval_seconds;
        save_config.reconnect_delay_seconds = config.reconnect_delay_seconds;
        save_config.max_reconnect_attempts = config.max_reconnect_attempts;
        save_config.auto_reconnect = config.auto_reconnect;
        save_config.redirect_gateway = config.redirect_gateway;
        save_config.routes = config.routes;
        save_config.dns_servers = config.dns_servers;
        
        if (config_mgr.save_client_config(default_config_path, save_config)) {
            std::cout << "Default configuration generated: " << default_config_path << std::endl;
        } else {
            std::cerr << "Failed to generate configuration file" << std::endl;
            return 1;
        }
        return 0;
    }
    
    // Load configuration file if specified
    if (!config_file.empty()) {
        vpn::ConfigManager::ClientConfig file_config;
        if (config_mgr.load_client_config(config_file, file_config)) {
            // Convert to VpnClient::Config
            config.server_address = file_config.server_address;
            config.server_port = file_config.server_port;
            config.tun_name = file_config.tun_name;
            config.tun_mtu = file_config.tun_mtu;
            config.connect_timeout_seconds = file_config.connect_timeout_seconds;
            config.keepalive_interval_seconds = file_config.keepalive_interval_seconds;
            config.reconnect_delay_seconds = file_config.reconnect_delay_seconds;
            config.max_reconnect_attempts = file_config.max_reconnect_attempts;
            config.auto_reconnect = file_config.auto_reconnect;
            config.redirect_gateway = file_config.redirect_gateway;
            config.routes = file_config.routes;
            config.dns_servers = file_config.dns_servers;
            
            std::cout << "Configuration loaded from: " << config_file << std::endl;
        } else {
            std::cerr << "Failed to load configuration file: " << config_file << std::endl;
            return 1;
        }
    }
    
    // Validate configuration
    vpn::ConfigManager::ClientConfig config_for_validation;
    config_for_validation.server_address = config.server_address;
    config_for_validation.server_port = config.server_port;
    config_for_validation.tun_mtu = config.tun_mtu;
    config_for_validation.connect_timeout_seconds = config.connect_timeout_seconds;
    
    std::string validation_error;
    if (!config_mgr.validate_client_config(config_for_validation, validation_error)) {
        std::cerr << "Configuration validation failed: " << validation_error << std::endl;
        return 1;
    }
    
    // Create client
    g_client = std::make_unique<vpn::VpnClient>(config);
    
    // Handle special operations
    if (show_status) {
        std::cout << g_client->get_connection_status() << std::endl;
        return 0;
    }
    
    if (test_connectivity) {
        if (g_client->test_connectivity()) {
            std::cout << "Connectivity test passed" << std::endl;
            return 0;
        } else {
            std::cout << "Connectivity test failed" << std::endl;
            return 1;
        }
    }
    
    // Check for root privileges (required for TUN interface creation and route management)
    if (geteuid() != 0) {
        std::cerr << "Warning: VPN client typically requires root privileges for TUN interface and routing" << std::endl;
        std::cerr << "Consider running with: sudo " << argv[0] << std::endl;
    }
    
    // Daemonize if requested
    if (daemon_mode) {
        if (daemon(0, 0) != 0) {
            std::cerr << "Failed to daemonize" << std::endl;
            return 1;
        }
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    
    std::cout << "Starting EleFP VPN Client" << std::endl;
    
    if (verbose || !daemon_mode) {
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Server: " << config.server_address << ":" << config.server_port << std::endl;
        std::cout << "  TUN interface: " << (config.tun_name.empty() ? "auto" : config.tun_name) << std::endl;
        std::cout << "  Redirect gateway: " << (config.redirect_gateway ? "yes" : "no") << std::endl;
        std::cout << "  Auto reconnect: " << (config.auto_reconnect ? "yes" : "no") << std::endl;
        std::cout << "  Connection timeout: " << config.connect_timeout_seconds << " seconds" << std::endl;
    }
    
    // Connect to server
    std::cout << "Connecting to VPN server..." << std::endl;
    
    if (!g_client->connect()) {
        std::cerr << "Failed to connect to VPN server: " << g_client->get_last_error() << std::endl;
        return 1;
    }
    
    std::cout << "Connected to VPN server successfully!" << std::endl;
    std::cout << "TUN interface: " << g_client->get_tun_interface_name() << std::endl;
    std::cout << "Assigned IP: " << g_client->get_assigned_ip() << std::endl;
    
    // Run until signal received or disconnected
    std::cout << "VPN client is connected. Press Ctrl+C to disconnect." << std::endl;
    
    while (g_client->is_connected()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (verbose) {
            // Print periodic status updates
            static int counter = 0;
            if (++counter % 60 == 0) { // Every 60 seconds
                auto stats = g_client->get_stats();
                std::cout << "Status: Connected for " << stats.connection_duration_seconds 
                          << "s, " << stats.packets_sent << " packets sent, "
                          << stats.packets_received << " packets received" << std::endl;
            }
        }
        
        // Check connection state
        auto state = g_client->get_connection_state();
        if (state == vpn::VpnClient::ConnectionState::ERROR) {
            std::cerr << "Connection error: " << g_client->get_last_error() << std::endl;
            break;
        } else if (state == vpn::VpnClient::ConnectionState::RECONNECTING && verbose) {
            std::cout << "Reconnecting to server..." << std::endl;
        }
    }
    
    std::cout << "VPN client disconnected" << std::endl;
    
    // Print final statistics
    if (verbose) {
        auto stats = g_client->get_stats();
        std::cout << "\nFinal Statistics:" << std::endl;
        std::cout << "  Total connection time: " << stats.connection_duration_seconds << " seconds" << std::endl;
        std::cout << "  Packets sent: " << stats.packets_sent << std::endl;
        std::cout << "  Packets received: " << stats.packets_received << std::endl;
        std::cout << "  Bytes sent: " << stats.bytes_sent << std::endl;
        std::cout << "  Bytes received: " << stats.bytes_received << std::endl;
        std::cout << "  Connection attempts: " << stats.connection_attempts << std::endl;
        std::cout << "  Reconnections: " << stats.reconnections << std::endl;
    }
    
    return 0;
}