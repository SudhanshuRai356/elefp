#include "vpn/ConfigManager.hpp"
#include <iostream>
#include <algorithm>
#include <regex>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <cstdlib>
using namespace std;

namespace vpn {

ConfigManager::ConfigManager() {}

bool ConfigManager::load_server_config(const string& file_path, ServerConfig& config) {
    config_file = file_path;
    values.clear();
    
    if (!parse_config_file(file_path)) {
        return false;  // couldnt parse the config file
    }
    
    // loading all the server config values with defaults
    config.listen_address = get_string_value("listen_address", "0.0.0.0");
    config.listen_port = get_uint16_value("listen_port", 1194);
    config.tun_name = get_string_value("tun_name", "");
    config.server_ip = get_string_value("server_ip", "10.8.0.1");
    config.server_netmask = get_string_value("server_netmask", "255.255.255.0");
    config.client_ip_range_start = get_string_value("client_ip_range_start", "10.8.0.10");
    config.client_ip_range_end = get_string_value("client_ip_range_end", "10.8.0.100");
    config.gateway = get_string_value("gateway", "10.8.0.1");
    
    config.max_clients = get_int_value("max_clients", 50);
    config.worker_threads = get_int_value("worker_threads", 4);
    config.tun_mtu = get_int_value("tun_mtu", 1500);
    config.session_timeout_seconds = get_uint32_value("session_timeout_seconds", 300);
    
    config.enable_internet_access = get_bool_value("enable_internet_access", true);
    config.dns_servers = get_string_list_value("dns_servers");
    if (config.dns_servers.empty()) {
        config.dns_servers = {"8.8.8.8", "8.8.4.4"};  // using google dns as default
    }
    
    config.log_level = get_string_value("log_level", "info");
    config.log_file = get_string_value("log_file", "");
    config.log_to_console = get_bool_value("log_to_console", true);
    
    config.keepalive_interval = get_uint32_value("keepalive_interval", 60);
    config.connection_timeout = get_uint32_value("connection_timeout", 120);
    
    return true;  // config loaded successfully
}

bool ConfigManager::load_client_config(const string& file_path, ClientConfig& config) {
    config_file = file_path;
    values.clear();
    
    if (!parse_config_file(file_path)) {
        return false;  // config file parsing failed
    }
    
    // loading client config values
    config.server_address = get_string_value("server_address", "127.0.0.1");
    config.server_port = get_uint16_value("server_port", 1194);
    config.tun_name = get_string_value("tun_name", "");
    config.tun_mtu = get_int_value("tun_mtu", 1500);
    
    config.connect_timeout_seconds = get_uint32_value("connect_timeout_seconds", 30);
    config.keepalive_interval_seconds = get_uint32_value("keepalive_interval_seconds", 60);
    config.reconnect_delay_seconds = get_uint32_value("reconnect_delay_seconds", 5);
    config.max_reconnect_attempts = get_uint32_value("max_reconnect_attempts", 10);
    config.auto_reconnect = get_bool_value("auto_reconnect", true);
    
    config.redirect_gateway = get_bool_value("redirect_gateway", true);
    config.routes = get_string_list_value("routes");
    config.dns_servers = get_string_list_value("dns_servers");
    if (config.dns_servers.empty()) {
        config.dns_servers = {"8.8.8.8", "8.8.4.4"};  // default dns
    }
    
    config.log_level = get_string_value("log_level", "info");
    config.log_file = get_string_value("log_file", "");
    config.log_to_console = get_bool_value("log_to_console", true);
    
    return true;  // client config loaded
}
    config.log_to_console = get_bool_value("log_to_console", true);
    
    return true;
}

bool ConfigManager::parse_config_file(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "Failed to open config file: " << file_path << std::endl;
        return false;
    }
    
    std::string line;
    int line_number = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        
        // Remove comments and trim whitespace
        size_t comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        if (line.empty()) continue;
        
        // Parse key=value pairs
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            std::cerr << "Invalid config line " << line_number << ": " << line << std::endl;
            continue;
        }
        
        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        
        // Trim whitespace from key and value
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        // Remove quotes if present
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }
        
        // Expand environment variables
        value = expand_environment_variables(value);
        
        config_values_[key] = value;
    }
    
    return true;
}

std::string ConfigManager::get_string_value(const std::string& key, const std::string& default_value) const {
    auto it = config_values_.find(key);
    return (it != config_values_.end()) ? it->second : default_value;
}

int ConfigManager::get_int_value(const std::string& key, int default_value) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            return std::stoi(it->second);
        } catch (const std::exception&) {
            std::cerr << "Invalid integer value for " << key << ": " << it->second << std::endl;
        }
    }
    return default_value;
}

bool ConfigManager::get_bool_value(const std::string& key, bool default_value) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        std::string value = it->second;
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
        return (value == "true" || value == "1" || value == "yes" || value == "on");
    }
    return default_value;
}

uint16_t ConfigManager::get_uint16_value(const std::string& key, uint16_t default_value) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            int value = std::stoi(it->second);
            if (value >= 0 && value <= 65535) {
                return static_cast<uint16_t>(value);
            }
        } catch (const std::exception&) {}
        std::cerr << "Invalid uint16 value for " << key << ": " << it->second << std::endl;
    }
    return default_value;
}

uint32_t ConfigManager::get_uint32_value(const std::string& key, uint32_t default_value) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            return std::stoul(it->second);
        } catch (const std::exception&) {
            std::cerr << "Invalid uint32 value for " << key << ": " << it->second << std::endl;
        }
    }
    return default_value;
}

std::vector<std::string> ConfigManager::get_string_list_value(const std::string& key) const {
    std::vector<std::string> result;
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        std::stringstream ss(it->second);
        std::string item;
        while (std::getline(ss, item, ',')) {
            // Trim whitespace
            item.erase(0, item.find_first_not_of(" \t"));
            item.erase(item.find_last_not_of(" \t") + 1);
            if (!item.empty()) {
                result.push_back(item);
            }
        }
    }
    return result;
}

bool ConfigManager::validate_ip_address(const std::string& ip) const {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1;
}

bool ConfigManager::validate_port(uint16_t port) const {
    return port > 0 && port <= 65535;
}

bool ConfigManager::validate_cidr(const std::string& cidr) const {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return validate_ip_address(cidr);
    }
    
    std::string ip = cidr.substr(0, slash_pos);
    std::string prefix = cidr.substr(slash_pos + 1);
    
    if (!validate_ip_address(ip)) return false;
    
    try {
        int prefix_len = std::stoi(prefix);
        return prefix_len >= 0 && prefix_len <= 32;
    } catch (const std::exception&) {
        return false;
    }
}

bool ConfigManager::validate_server_config(const ServerConfig& config, std::string& error_message) const {
    if (!validate_ip_address(config.listen_address)) {
        error_message = "Invalid listen address: " + config.listen_address;
        return false;
    }
    
    if (!validate_port(config.listen_port)) {
        error_message = "Invalid listen port: " + std::to_string(config.listen_port);
        return false;
    }
    
    if (!validate_ip_address(config.server_ip)) {
        error_message = "Invalid server IP: " + config.server_ip;
        return false;
    }
    
    if (!validate_ip_address(config.server_netmask)) {
        error_message = "Invalid server netmask: " + config.server_netmask;
        return false;
    }
    
    if (!validate_ip_address(config.client_ip_range_start)) {
        error_message = "Invalid client IP range start: " + config.client_ip_range_start;
        return false;
    }
    
    if (!validate_ip_address(config.client_ip_range_end)) {
        error_message = "Invalid client IP range end: " + config.client_ip_range_end;
        return false;
    }
    
    if (config.max_clients <= 0 || config.max_clients > 1000) {
        error_message = "Invalid max clients: " + std::to_string(config.max_clients);
        return false;
    }
    
    if (config.worker_threads <= 0 || config.worker_threads > 32) {
        error_message = "Invalid worker threads: " + std::to_string(config.worker_threads);
        return false;
    }
    
    if (config.tun_mtu < 576 || config.tun_mtu > 9000) {
        error_message = "Invalid TUN MTU: " + std::to_string(config.tun_mtu);
        return false;
    }
    
    return true;
}

bool ConfigManager::validate_client_config(const ClientConfig& config, std::string& error_message) const {
    if (!validate_ip_address(config.server_address) && config.server_address != "localhost") {
        // Also allow hostnames, not just IP addresses
        if (config.server_address.empty()) {
            error_message = "Server address cannot be empty";
            return false;
        }
    }
    
    if (!validate_port(config.server_port)) {
        error_message = "Invalid server port: " + std::to_string(config.server_port);
        return false;
    }
    
    if (config.tun_mtu < 576 || config.tun_mtu > 9000) {
        error_message = "Invalid TUN MTU: " + std::to_string(config.tun_mtu);
        return false;
    }
    
    if (config.connect_timeout_seconds == 0 || config.connect_timeout_seconds > 300) {
        error_message = "Invalid connect timeout: " + std::to_string(config.connect_timeout_seconds);
        return false;
    }
    
    return true;
}

ConfigManager::ServerConfig ConfigManager::get_default_server_config() {
    return ServerConfig{}; // Uses default values from struct
}

ConfigManager::ClientConfig ConfigManager::get_default_client_config() {
    return ClientConfig{}; // Uses default values from struct
}

bool ConfigManager::save_server_config(const std::string& file_path, const ServerConfig& config) {
    std::ofstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# VPN Server Configuration\n";
    file << "# Generated by elefp VPN\n\n";
    
    file << "# Network Settings\n";
    file << "listen_address = " << config.listen_address << "\n";
    file << "listen_port = " << config.listen_port << "\n";
    file << "tun_name = " << config.tun_name << "\n";
    file << "server_ip = " << config.server_ip << "\n";
    file << "server_netmask = " << config.server_netmask << "\n";
    file << "client_ip_range_start = " << config.client_ip_range_start << "\n";
    file << "client_ip_range_end = " << config.client_ip_range_end << "\n";
    file << "gateway = " << config.gateway << "\n\n";
    
    file << "# Performance Settings\n";
    file << "max_clients = " << config.max_clients << "\n";
    file << "worker_threads = " << config.worker_threads << "\n";
    file << "tun_mtu = " << config.tun_mtu << "\n";
    file << "session_timeout_seconds = " << config.session_timeout_seconds << "\n\n";
    
    file << "# Features\n";
    file << "enable_internet_access = " << (config.enable_internet_access ? "true" : "false") << "\n";
    
    file << "dns_servers = ";
    for (size_t i = 0; i < config.dns_servers.size(); ++i) {
        if (i > 0) file << ",";
        file << config.dns_servers[i];
    }
    file << "\n\n";
    
    file << "# Logging\n";
    file << "log_level = " << config.log_level << "\n";
    file << "log_file = " << config.log_file << "\n";
    file << "log_to_console = " << (config.log_to_console ? "true" : "false") << "\n\n";
    
    file << "# Security\n";
    file << "keepalive_interval = " << config.keepalive_interval << "\n";
    file << "connection_timeout = " << config.connection_timeout << "\n";
    
    return file.good();
}

bool ConfigManager::save_client_config(const std::string& file_path, const ClientConfig& config) {
    std::ofstream file(file_path);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# VPN Client Configuration\n";
    file << "# Generated by elefp VPN\n\n";
    
    file << "# Connection Settings\n";
    file << "server_address = " << config.server_address << "\n";
    file << "server_port = " << config.server_port << "\n";
    file << "tun_name = " << config.tun_name << "\n";
    file << "tun_mtu = " << config.tun_mtu << "\n\n";
    
    file << "# Timeouts and Reconnection\n";
    file << "connect_timeout_seconds = " << config.connect_timeout_seconds << "\n";
    file << "keepalive_interval_seconds = " << config.keepalive_interval_seconds << "\n";
    file << "reconnect_delay_seconds = " << config.reconnect_delay_seconds << "\n";
    file << "max_reconnect_attempts = " << config.max_reconnect_attempts << "\n";
    file << "auto_reconnect = " << (config.auto_reconnect ? "true" : "false") << "\n\n";
    
    file << "# Routing\n";
    file << "redirect_gateway = " << (config.redirect_gateway ? "true" : "false") << "\n";
    
    file << "routes = ";
    for (size_t i = 0; i < config.routes.size(); ++i) {
        if (i > 0) file << ",";
        file << config.routes[i];
    }
    file << "\n";
    
    file << "dns_servers = ";
    for (size_t i = 0; i < config.dns_servers.size(); ++i) {
        if (i > 0) file << ",";
        file << config.dns_servers[i];
    }
    file << "\n\n";
    
    file << "# Logging\n";
    file << "log_level = " << config.log_level << "\n";
    file << "log_file = " << config.log_file << "\n";
    file << "log_to_console = " << (config.log_to_console ? "true" : "false") << "\n";
    
    return file.good();
}

std::string ConfigManager::expand_environment_variables(const std::string& str) {
    std::string result = str;
    std::regex env_regex(R"(\$\{([^}]*)\})");
    std::smatch match;
    
    while (std::regex_search(result, match, env_regex)) {
        std::string var_name = match[1].str();
        const char* env_value = getenv(var_name.c_str());
        std::string replacement = env_value ? env_value : "";
        
        result.replace(match.position(), match.length(), replacement);
    }
    
    return result;
}

bool ConfigManager::create_config_directory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    
    return mkdir(path.c_str(), 0755) == 0;
}

std::string ConfigManager::get_default_config_dir() {
    const char* home = getenv("HOME");
    if (home) {
        return std::string(home) + "/.config/elefp";
    }
    return "/etc/elefp";
}

std::string ConfigManager::get_default_server_config_path() {
    return get_default_config_dir() + "/server.conf";
}

std::string ConfigManager::get_default_client_config_path() {
    return get_default_config_dir() + "/client.conf";
}

} // namespace vpn