#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <cstdint>

namespace vpn {

struct IpRange {
    uint32_t start;
    uint32_t end;
    uint32_t netmask;
    std::string gateway;
    
    IpRange(const std::string& start_ip, const std::string& end_ip, 
            const std::string& netmask_str, const std::string& gateway_ip);
    
    bool contains(uint32_t ip) const;
    size_t size() const;
};

class IpPool {
private:
    std::vector<IpRange> ranges;                // ip ranges we can allocate from
    std::unordered_set<uint32_t> allocated;    // which ips are currently taken
    std::unordered_map<std::string, uint32_t> clients;  // client_id -> ip mapping
    std::unordered_map<uint32_t, std::string> ips;      // ip -> client_id mapping
    mutable std::mutex mtx;                     // mutex for thread safety
    uint32_t lease_time;                        // how long to keep ips allocated
    
    uint32_t find_free_ip() const;             // finds a free ip in the ranges
    
public:
    IpPool();
    
    // managing ip ranges
    bool add_range(const std::string& start_ip, const std::string& end_ip,
                   const std::string& netmask, const std::string& gateway);
    void clear_ranges();
    
    // allocating and releasing ips
    std::string allocate_ip(const std::string& client_id);
    bool release_ip(const std::string& client_id);
    bool release_ip_address(const std::string& ip);
    
    // getting ip info
    std::string get_client_ip(const std::string& client_id) const;
    std::string get_ip_client(const std::string& ip) const;
    bool is_ip_allocated(const std::string& ip) const;
    
    // pool status
    size_t total_ips() const;
    size_t allocated_count() const;
    size_t available_count() const;
    std::vector<std::string> get_allocated_ips() const;
    
    // lease time management
    void set_lease_time(uint32_t seconds) { lease_time = seconds; }
    uint32_t get_lease_time() const { return lease_time; }
    
    // network config stuff
    std::string get_gateway_for_ip(const std::string& ip) const;
    std::string get_netmask_for_ip(const std::string& ip) const;
    
    // utility functions for ip conversion
    static uint32_t ip_to_uint32(const std::string& ip);
    static std::string uint32_to_ip(uint32_t ip);
    static uint32_t netmask_to_uint32(const std::string& netmask);
};

} // namespace vpn