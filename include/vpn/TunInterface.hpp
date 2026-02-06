#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace vpn {

class TunInterface {
private:
    int fd;             // file descriptor for the tun device
    std::string name;   // name of the interface like tun0
    std::string ip;     // ip address assigned to this interface
    std::string mask;   // netmask for the interface
    bool is_up;         // whether the interface is open and configured
    
    bool create_interface();
    bool configure_interface(const std::string& ip, const std::string& netmask);
    bool set_interface_up();
    
public:
    TunInterface();
    ~TunInterface();
    
    // cant copy tun interfaces since each has unique file descriptor
    TunInterface(const TunInterface&) = delete;
    TunInterface& operator=(const TunInterface&) = delete;
    
    // but we can move them around
    TunInterface(TunInterface&& other) noexcept;
    TunInterface& operator=(TunInterface&& other) noexcept;
    
    // interface management
    bool open(const std::string& interface_name = "");
    void close();
    bool configure(const std::string& ip, const std::string& netmask, int mtu = 1500);
    
    // reading and writing packets
    ssize_t read_packet(std::vector<uint8_t>& packet);
    ssize_t write_packet(const std::vector<uint8_t>& packet);
    
    // checking status and getting info
    bool is_open() const { return is_up; }
    const std::string& get_interface_name() const { return name; }
    const std::string& get_ip_address() const { return ip; }
    int get_fd() const { return fd; }
    
    // utility functions for managing interfaces and routes
    static std::string get_next_available_name(const std::string& prefix = "tun");
    static bool add_route(const std::string& dest, const std::string& gateway, const std::string& interface);
    static bool delete_route(const std::string& dest, const std::string& gateway, const std::string& interface);
};

} // namespace vpn