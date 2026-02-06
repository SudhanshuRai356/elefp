#include "vpn/VpnServer.hpp"
#include "vpn/ConfigManager.hpp"
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <thread>
#include <chrono>

std::unique_ptr<vpn::VpnServer> g_server;

void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
    if (g_server) {
        g_server->stop();
    }
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -c, --config FILE    Configuration file path" << std::endl;
    std::cout << "  -p, --port PORT      Listen port (default: 1194)" << std::endl;
    std::cout << "  -a, --address ADDR   Listen address (default: 0.0.0.0)" << std::endl;
    std::cout << "  -i, --interface NAME TUN interface name" << std::endl;
    std::cout << "  -m, --max-clients N  Maximum number of clients (default: 50)" << std::endl;
    std::cout << "  -t, --threads N      Number of worker threads (default: 4)" << std::endl;
    std::cout << "  -d, --daemon         Run as daemon (background)" << std::endl;
    std::cout << "  -v, --verbose        Verbose output" << std::endl;
    std::cout << "  -h, --help           Show this help" << std::endl;
    std::cout << "  --generate-config    Generate default configuration file" << std::endl;
}

int main(int argc, char* argv[]) {
    vpn::VpnServer::Config config;
    vpn::ConfigManager config_mgr;
    std::string config_file = "";
    bool daemon_mode = false;
    bool verbose = false;
    bool generate_config = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--generate-config") {
            generate_config = true;
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_file = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires a file path" << std::endl;
                return 1;
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                config.listen_port = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: " << arg << " requires a port number" << std::endl;
                return 1;
            }
        } else if (arg == "-a" || arg == "--address") {
            if (i + 1 < argc) {
                config.listen_address = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an address" << std::endl;
                return 1;
            }
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                config.tun_name = argv[++i];
            } else {
                std::cerr << "Error: " << arg << " requires an interface name" << std::endl;
                return 1;
            }
        } else if (arg == "-m" || arg == "--max-clients") {
            if (i + 1 < argc) {
                config.max_clients = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: " << arg << " requires a number" << std::endl;
                return 1;
            }
        } else if (arg == "-t" || arg == "--threads") {
            if (i + 1 < argc) {
                config.worker_threads = std::stoi(argv[++i]);
            } else {
                std::cerr << "Error: " << arg << " requires a number" << std::endl;
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
        std::string default_config_path = vpn::ConfigManager::get_default_server_config_path();
        
        // Create config directory if it doesn't exist
        size_t last_slash = default_config_path.find_last_of('/');
        if (last_slash != std::string::npos) {
            std::string config_dir = default_config_path.substr(0, last_slash);
            vpn::ConfigManager::create_config_directory(config_dir);
        }
        
        // Convert to ConfigManager::ServerConfig for saving
        vpn::ConfigManager::ServerConfig save_config;
        save_config.listen_address = config.listen_address;
        save_config.listen_port = config.listen_port;
        save_config.tun_name = config.tun_name;
        save_config.server_ip = config.server_ip;
        save_config.server_netmask = config.server_netmask;
        save_config.client_ip_range_start = config.client_ip_range_start;
        save_config.client_ip_range_end = config.client_ip_range_end;
        save_config.gateway = config.gateway;
        save_config.max_clients = config.max_clients;
        save_config.worker_threads = config.worker_threads;
        save_config.tun_mtu = config.tun_mtu;
        save_config.enable_internet_access = config.enable_internet_access;
        save_config.dns_servers = config.dns_servers;
        save_config.session_timeout_seconds = config.session_timeout_seconds;
        
        if (config_mgr.save_server_config(default_config_path, save_config)) {
            std::cout << "Default configuration generated: " << default_config_path << std::endl;
        } else {
            std::cerr << "Failed to generate configuration file" << std::endl;
            return 1;
        }
        return 0;
    }
    
    // Load configuration file if specified
    if (!config_file.empty()) {
        vpn::ConfigManager::ServerConfig file_config;
        if (config_mgr.load_server_config(config_file, file_config)) {
            // Convert to VpnServer::Config
            config.listen_address = file_config.listen_address;
            config.listen_port = file_config.listen_port;
            config.tun_name = file_config.tun_name;
            config.server_ip = file_config.server_ip;
            config.server_netmask = file_config.server_netmask;
            config.client_ip_range_start = file_config.client_ip_range_start;
            config.client_ip_range_end = file_config.client_ip_range_end;
            config.gateway = file_config.gateway;
            config.max_clients = file_config.max_clients;
            config.worker_threads = file_config.worker_threads;
            config.tun_mtu = file_config.tun_mtu;
            config.session_timeout_seconds = file_config.session_timeout_seconds;
            config.enable_internet_access = file_config.enable_internet_access;
            config.dns_servers = file_config.dns_servers;
            
            std::cout << "Configuration loaded from: " << config_file << std::endl;
        } else {
            std::cerr << "Failed to load configuration file: " << config_file << std::endl;
            return 1;
        }
    }
    
    // Validate configuration
    vpn::ConfigManager::ServerConfig config_for_validation;
    config_for_validation.listen_address = config.listen_address;
    config_for_validation.listen_port = config.listen_port;
    config_for_validation.server_ip = config.server_ip;
    config_for_validation.server_netmask = config.server_netmask;
    config_for_validation.client_ip_range_start = config.client_ip_range_start;
    config_for_validation.client_ip_range_end = config.client_ip_range_end;
    config_for_validation.max_clients = config.max_clients;
    config_for_validation.worker_threads = config.worker_threads;
    config_for_validation.tun_mtu = config.tun_mtu;
    
    std::string validation_error;
    if (!config_mgr.validate_server_config(config_for_validation, validation_error)) {
        std::cerr << "Configuration validation failed: " << validation_error << std::endl;
        return 1;
    }
    
    // Check for root privileges (required for TUN interface creation)
    if (geteuid() != 0) {
        std::cerr << "Warning: VPN server typically requires root privileges for TUN interface management" << std::endl;
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
    
    std::cout << "Starting EleFP VPN Server" << std::endl;
    
    if (verbose || !daemon_mode) {
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Listen: " << config.listen_address << ":" << config.listen_port << std::endl;
        std::cout << "  TUN interface: " << (config.tun_name.empty() ? "auto" : config.tun_name) << std::endl;
        std::cout << "  Server IP: " << config.server_ip << "/" << config.server_netmask << std::endl;
        std::cout << "  Client IP range: " << config.client_ip_range_start 
                  << " - " << config.client_ip_range_end << std::endl;
        std::cout << "  Max clients: " << config.max_clients << std::endl;
        std::cout << "  Worker threads: " << config.worker_threads << std::endl;
        std::cout << "  Internet access: " << (config.enable_internet_access ? "enabled" : "disabled") << std::endl;
    }
    
    // Create and start server
    g_server = std::make_unique<vpn::VpnServer>(config);
    
    if (!g_server->start()) {
        std::cerr << "Failed to start VPN server" << std::endl;
        return 1;
    }
    
    // Run until signal received
    std::cout << "VPN server is running. Press Ctrl+C to stop." << std::endl;
    
    while (g_server->is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if (verbose) {
            // Print periodic status updates
            static int counter = 0;
            if (++counter % 60 == 0) { // Every 60 seconds
                auto stats = g_server->get_stats();
                std::cout << "Status: " << stats.active_clients << " clients, "
                          << stats.packets_received << " packets received" << std::endl;
            }
        }
    }
    
    std::cout << "VPN server stopped" << std::endl;
    return 0;
}