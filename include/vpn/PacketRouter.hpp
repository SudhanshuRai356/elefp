#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <cstdint>

namespace vpn {

struct IpHeader {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
    
    static IpHeader parse(const std::vector<uint8_t>& packet);  // parse ip header from packet
    static bool is_valid_packet(const std::vector<uint8_t>& packet);  // check if packet looks ok
};

struct RouteEntry {
    uint32_t dest_network;
    uint32_t netmask;
    uint32_t gateway;
    std::string interface;
    int metric;
    
    bool matches(uint32_t dest_ip) const;  // check if ip matches this route
};

class PacketRouter {
private:
    std::vector<RouteEntry> routes;                           // routing table entries
    std::unordered_map<uint32_t, std::string> ip_to_client; // which client has what ip
    std::unordered_map<std::string, uint32_t> client_to_ip; // what ip each client has
    mutable std::mutex mtx;                                  // thread safety for client maps
    
    // nat stuff for connecting to internet
    struct NatEntry {
        std::string client_id;     // which client this nat entry belongs to  
        uint32_t internal_ip;      // clients real ip inside vpn
        uint16_t internal_port;    // clients real port
        uint16_t external_port;    // what port we use when talking to internet
        uint8_t protocol;          // tcp or udp
        time_t last_activity;      // when this connection was last used
    };
    
    std::unordered_map<uint32_t, NatEntry> nat_table;       // external port -> nat entry
    std::unordered_map<uint64_t, uint16_t> connections;     // connection key -> external port
    mutable std::mutex nat_mtx;                             // thread safety for nat
    uint16_t next_port;                                     // next external port to try
    
    uint32_t make_port_key(uint16_t port, uint8_t protocol) const;
    uint64_t make_connection_key(uint32_t ip, uint16_t port, uint8_t protocol) const;
    
    bool route_to_internet(std::vector<uint8_t>& packet, const std::string& client_id);
    bool route_from_internet(std::vector<uint8_t>& packet);
    bool route_between_clients(const std::vector<uint8_t>& packet, const std::string& source_client);
    
    void update_nat_for_outbound(std::vector<uint8_t>& packet, const std::string& client_id);
    bool update_nat_for_inbound(std::vector<uint8_t>& packet);
    
    void cleanup_expired_nat_entries();
    
public:
    PacketRouter();
    
    // managing clients and their ips
    void add_client(const std::string& client_id, uint32_t ip_address);
    void remove_client(const std::string& client_id);
    bool has_client(const std::string& client_id) const;
    std::string get_client_for_ip(uint32_t ip) const;
    uint32_t get_ip_for_client(const std::string& client_id) const;
    
    // managing routes  
    void add_route(const std::string& dest_network, const std::string& netmask,
                   const std::string& gateway, const std::string& interface, int metric = 0);
    void remove_route(const std::string& dest_network, const std::string& netmask);
    void clear_routes();
    
    // routing packets around
    enum class RouteResult {
        TO_CLIENT,      // send to another vpn client
        TO_INTERNET,    // send to internet with nat
        DROP,           // packet is bad, drop it
        ERROR           // something went wrong
    };
    
    RouteResult route_packet(std::vector<uint8_t>& packet, const std::string& source_client, std::string& target_client);
    RouteResult route_inbound_packet(std::vector<uint8_t>& packet, std::string& target_client);
    
    // stats for monitoring
    struct Stats {
        uint64_t packets_routed_to_clients = 0;   // how many packets sent to clients
        uint64_t packets_routed_to_internet = 0;  // how many packets sent to internet
        uint64_t packets_dropped = 0;             // how many bad packets we dropped
        uint64_t nat_entries_active = 0;          // how many nat connections active
        uint64_t nat_entries_expired = 0;         // how many nat entries timed out
    };
    
    Stats get_stats() const;
    void reset_stats();
    
    // helper functions for ip stuff
    static uint32_t ip_string_to_uint32(const std::string& ip);
    static std::string ip_uint32_to_string(uint32_t ip);
    static uint16_t calculate_ip_checksum(const std::vector<uint8_t>& packet);
    static void update_ip_checksum(std::vector<uint8_t>& packet);
    
private:
    mutable Stats stats;         // stats we keep track of
    mutable std::mutex stats_mtx; // thread safety for stats
};

} // namespace vpn