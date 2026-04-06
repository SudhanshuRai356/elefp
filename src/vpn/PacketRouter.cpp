#include "vpn/PacketRouter.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
#include <iostream>
using namespace std;

namespace vpn {

IpHeader IpHeader::parse(const vector<uint8_t>& packet) {
    if (packet.size() < 20) {
        throw runtime_error("packet too small for ip header, need at least 20 bytes");
    }
    
    IpHeader header;
    header.version_ihl = packet[0];
    header.tos = packet[1];
    header.total_length = (packet[2] << 8) | packet[3];      // combining bytes to get length
    header.identification = (packet[4] << 8) | packet[5];
    header.flags_fragment = (packet[6] << 8) | packet[7];
    header.ttl = packet[8];
    header.protocol = packet[9];
    header.checksum = (packet[10] << 8) | packet[11];
    
    memcpy(&header.source_ip, &packet[12], 4);   // copying source ip
    memcpy(&header.dest_ip, &packet[16], 4);     // copying dest ip
    
    header.source_ip = ntohl(header.source_ip);  // converting from network byte order
    header.dest_ip = ntohl(header.dest_ip);
    
    return header;
}

bool IpHeader::is_valid_packet(const vector<uint8_t>& packet) {
    if (packet.size() < 20) return false;  // too small for ip header
    
    uint8_t version = (packet[0] >> 4) & 0xF;
    if (version != 4) return false;  // only handling ipv4 for now
    
    uint8_t ihl = packet[0] & 0xF;   // internet header length
    if (ihl < 5 || ihl * 4 > packet.size()) return false;  // header length doesnt make sense
    
    uint16_t total_length = (packet[2] << 8) | packet[3];
    if (total_length > packet.size()) return false;  // says its longer than it actually is
    
    return true;  // packet looks legit
}

bool RouteEntry::matches(uint32_t dest_ip) const {
    return (dest_ip & netmask) == (dest_network & netmask);  // checking if dest ip is in this network
}

PacketRouter::PacketRouter() : next_port(32768) {}  // starting with port 32768 for external connections

void PacketRouter::add_client(const string& client_id, uint32_t ip_address) {
    lock_guard<mutex> lock(mtx);
    
    // removing old mapping if this client already has an ip
    auto old_ip_it = client_to_ip.find(client_id);
    if (old_ip_it != client_to_ip.end()) {
        ip_to_client.erase(old_ip_it->second);  // clean up reverse mapping too
    }
    
    // adding new mappings both ways
    client_to_ip[client_id] = ip_address;
    ip_to_client[ip_address] = client_id;
}

void PacketRouter::remove_client(const string& client_id) {
    lock_guard<mutex> lock(mtx);
    
    auto it = client_to_ip.find(client_id);
    if (it != client_to_ip.end()) {
        ip_to_client.erase(it->second);  // removing reverse mapping
        client_to_ip.erase(it);          // removing forward mapping
    }
}

bool PacketRouter::has_client(const string& client_id) const {
    lock_guard<mutex> lock(mtx);
    return client_to_ip.find(client_id) != client_to_ip.end();  // checking if we know this client
}

string PacketRouter::get_client_for_ip(uint32_t ip) const {
    lock_guard<mutex> lock(mtx);
    auto it = ip_to_client.find(ip);
    return (it != ip_to_client.end()) ? it->second : "";  // return client id or empty if not found
}

uint32_t PacketRouter::get_ip_for_client(const string& client_id) const {
    lock_guard<mutex> lock(mtx);
    auto it = client_to_ip.find(client_id);
    return (it != client_to_ip.end()) ? it->second : 0;   // return ip or 0 if not found
}

void PacketRouter::add_route(const string& dest_network, const string& netmask,
                            const string& gateway, const string& interface, int metric) {
    lock_guard<mutex> lock(mtx);
    
    RouteEntry entry;
    entry.dest_network = ip_string_to_uint32(dest_network);
    entry.netmask = ip_string_to_uint32(netmask);
    entry.gateway = ip_string_to_uint32(gateway);
    entry.interface = interface;
    entry.metric = metric;
    
    routes.push_back(entry);
    
    // sorting by metric so lower metric routes get priority
    sort(routes.begin(), routes.end(), 
              [](const RouteEntry& a, const RouteEntry& b) {
                  return a.metric < b.metric;
              });
}

void PacketRouter::remove_route(const string& dest_network, const string& netmask) {
    lock_guard<mutex> lock(mtx);
    
    uint32_t dest_net = ip_string_to_uint32(dest_network);
    uint32_t net_mask = ip_string_to_uint32(netmask);
    
    routes.erase(remove_if(routes.begin(), routes.end(),
                           [dest_net, net_mask](const RouteEntry& route) {
                               return route.dest_network == dest_net && 
                                      route.netmask == net_mask;
                           }), routes.end());
}

void PacketRouter::clear_routes() {
    lock_guard<mutex> lock(mtx);
    routes.clear();  // clearing all routes
}

uint32_t PacketRouter::make_port_key(uint16_t port, uint8_t protocol) const {
    return (static_cast<uint32_t>(protocol) << 16) | port;  // combining protocol and port into one key
}

uint64_t PacketRouter::make_connection_key(uint32_t ip, uint16_t port, uint8_t protocol) const {
    return (static_cast<uint64_t>(ip) << 32) | 
           (static_cast<uint64_t>(port) << 16) | 
           protocol;  // combining ip, port, and protocol into connection identifier
}

PacketRouter::RouteResult PacketRouter::route_packet(vector<uint8_t>& packet, 
                                                    const string& source_client, 
                                                    string& target_client) {
    lock_guard<mutex> stats_lock(stats_mtx);
    
    if (!IpHeader::is_valid_packet(packet)) {
        stats.packets_dropped++;
        return RouteResult::DROP;  // packet looks corrupted, dropping it
    }
    
    IpHeader header = IpHeader::parse(packet);
    
    // checking if destination is another vpn client
    target_client = get_client_for_ip(header.dest_ip);
    if (!target_client.empty() && target_client != source_client) {
        stats.packets_routed_to_clients++;
        return RouteResult::TO_CLIENT;  // sending to another client
    }
    
    // trying to route to internet with nat
    if (route_to_internet(packet, source_client)) {
        stats.packets_routed_to_internet++;
        return RouteResult::TO_INTERNET;  // sent to internet
    }
    
    stats.packets_dropped++;
    return RouteResult::DROP;  // couldnt route anywhere, dropping
}

PacketRouter::RouteResult PacketRouter::route_inbound_packet(vector<uint8_t>& packet, 
                                                            string& target_client) {
    lock_guard<mutex> stats_lock(stats_mtx);
    
    if (!IpHeader::is_valid_packet(packet)) {
        stats.packets_dropped++;
        return RouteResult::DROP;  // bad packet from internet
    }
    
    if (route_from_internet(packet)) {
        IpHeader header = IpHeader::parse(packet);
        target_client = get_client_for_ip(header.dest_ip);
        if (!target_client.empty()) {
            stats.packets_routed_to_clients++;
            return RouteResult::TO_CLIENT;  // found the client for this packet
        }
    }
    
    stats.packets_dropped++;
    return RouteResult::DROP;  // couldnt find where to deliver this
}

bool PacketRouter::route_to_internet(vector<uint8_t>& packet, const string& client_id) {
    (void)packet;
    (void)client_id;
    // Transport-level NAT is handled by kernel conntrack/iptables on the server.
    // Do not rewrite L4 ports/checksums here or return traffic will not map correctly
    // to client-side sockets.
    return true;
}

bool PacketRouter::route_from_internet(vector<uint8_t>& packet) {
    (void)packet;
    // Reverse translation is also handled by kernel conntrack/iptables.
    return true;
}

void PacketRouter::update_nat_for_outbound(vector<uint8_t>& packet, const string& client_id) {
    if (packet.size() < 20) return;  // packet too small
    
    IpHeader header = IpHeader::parse(packet);
    
    // only handling tcp and udp for now, other protocols are too weird
    if (header.protocol != 6 && header.protocol != 17) return;
    
    if (packet.size() < 28) return;  // need ip + tcp/udp header
    
    uint16_t source_port = (packet[20] << 8) | packet[21];  // getting source port from packet
    uint64_t conn_key = make_connection_key(header.source_ip, source_port, header.protocol);
    
    lock_guard<mutex> nat_lock(nat_mtx);
    
    uint16_t external_port;
    auto conn_it = connections.find(conn_key);
    
    if (conn_it != connections.end()) {
        // this connection already exists, reusing the same external port
        external_port = conn_it->second;
        auto& nat_entry = nat_table[make_port_key(external_port, header.protocol)];
        nat_entry.last_activity = time(nullptr);  // updating activity time
    } else {
        // new connection, need to find an available external port
        do {
            external_port = next_port++;
            if (next_port > 65535) {
                next_port = 32768;  // wrapping around to start of dynamic port range
            }
        } while (nat_table.find(make_port_key(external_port, header.protocol)) != nat_table.end());
        
        // creating new nat entry for this connection
        NatEntry entry;
        entry.client_id = client_id;
        entry.internal_ip = header.source_ip;
        entry.internal_port = source_port;
        entry.external_port = external_port;
        entry.protocol = header.protocol;
        entry.last_activity = time(nullptr);
        
        nat_table[make_port_key(external_port, header.protocol)] = entry;
        connections[conn_key] = external_port;
    }
    
    // updating packet to use external port instead of internal port
    packet[20] = (external_port >> 8) & 0xFF;
    packet[21] = external_port & 0xFF;
    
    // clearing checksums so they get recalculated properly
    packet[10] = packet[11] = 0;  // ip checksum
    if (header.protocol == 6) {   // tcp
        packet[36] = packet[37] = 0;  // tcp checksum
    } else if (header.protocol == 17) {  // udp
        packet[26] = packet[27] = 0;  // udp checksum
    }
}

bool PacketRouter::update_nat_for_inbound(vector<uint8_t>& packet) {
    if (packet.size() < 20) return false;  // packet too small
    
    IpHeader header = IpHeader::parse(packet);
    
    // only handling tcp and udp
    if (header.protocol != 6 && header.protocol != 17) return false;
    
    if (packet.size() < 28) return false;  // need full headers
    
    uint16_t dest_port = (packet[22] << 8) | packet[23];  // destination port from packet
    uint32_t port_key = make_port_key(dest_port, header.protocol);
    
    lock_guard<mutex> nat_lock(nat_mtx);
    
    auto nat_it = nat_table.find(port_key);
    if (nat_it == nat_table.end()) {
        return false;  // no nat entry for this port, packet doesnt belong to us
    }
    
    NatEntry& entry = nat_it->second;
    entry.last_activity = time(nullptr);  // updating activity time
    
    // changing packet destination to internal ip and port
    uint32_t internal_ip_be = htonl(entry.internal_ip);
    memcpy(&packet[16], &internal_ip_be, 4);  // updating dest ip
    
    packet[22] = (entry.internal_port >> 8) & 0xFF;  // updating dest port high byte
    packet[23] = entry.internal_port & 0xFF;         // updating dest port low byte
    
    // clearing checksums so they get recalculated
    packet[10] = packet[11] = 0;  // ip checksum
    if (header.protocol == 6) {
        packet[36] = packet[37] = 0;  // tcp checksum
    } else if (header.protocol == 17) {
        packet[26] = packet[27] = 0;  // udp checksum
    }
    
    return true;  // successfully translated packet
}

void PacketRouter::cleanup_expired_nat_entries() {
    lock_guard<mutex> nat_lock(nat_mtx);
    
    time_t now = time(nullptr);
    const time_t timeout = 300;  // 5 minutes timeout for inactive connections
    
    auto nat_it = nat_table.begin();
    while (nat_it != nat_table.end()) {
        if (now - nat_it->second.last_activity > timeout) {
            // this connection has been idle too long, cleaning it up
            uint64_t conn_key = make_connection_key(nat_it->second.internal_ip, 
                                                   nat_it->second.internal_port,
                                                   nat_it->second.protocol);
            connections.erase(conn_key);  // removing from connection map
            
            nat_it = nat_table.erase(nat_it);  // removing nat entry
            
            lock_guard<mutex> stats_lock(stats_mtx);
            stats.nat_entries_expired++;  // updating stats
        } else {
            ++nat_it;  // keeping this entry, moving to next
        }
    }
}

PacketRouter::Stats PacketRouter::get_stats() const {
    lock_guard<mutex> stats_lock(stats_mtx);
    lock_guard<mutex> nat_lock(nat_mtx);
    
    Stats current_stats = stats;
    current_stats.nat_entries_active = nat_table.size();  // adding current active connections
    return current_stats;
}

void PacketRouter::reset_stats() {
    lock_guard<mutex> stats_lock(stats_mtx);
    stats = Stats{};  // resetting all stats to zero
}

uint32_t PacketRouter::ip_string_to_uint32(const string& ip) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
        throw runtime_error("couldnt convert ip string to number: " + ip);
    }
    return ntohl(sa.sin_addr.s_addr);  // converting from network byte order
}

string PacketRouter::ip_uint32_to_string(uint32_t ip) {
    struct sockaddr_in sa;
    sa.sin_addr.s_addr = htonl(ip);  // converting to network byte order
    char buffer[INET_ADDRSTRLEN];
    
    if (inet_ntop(AF_INET, &sa.sin_addr, buffer, sizeof(buffer)) == nullptr) {
        throw runtime_error("couldnt convert ip number to string");
    }
    
    return string(buffer);
}

uint16_t PacketRouter::calculate_ip_checksum(const vector<uint8_t>& packet) {
    if (packet.size() < 20) return 0;  // packet too small for ip header
    
    uint32_t sum = 0;
    
    // summing all 16-bit words in header except checksum field
    for (int i = 0; i < 20; i += 2) {
        if (i == 10) continue;  // skipping checksum field itself
        
        uint16_t word = (packet[i] << 8) | packet[i + 1];
        sum += word;
    }
    
    // handling carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;  // returning ones complement
}

void PacketRouter::update_ip_checksum(vector<uint8_t>& packet) {
    if (packet.size() < 20) return;  // cant checksum incomplete packet
    
    // clearing old checksum
    packet[10] = packet[11] = 0;
    
    // calculating new checksum
    uint16_t checksum = calculate_ip_checksum(packet);
    
    // putting new checksum back in packet
    packet[10] = (checksum >> 8) & 0xFF;
    packet[11] = checksum & 0xFF;
}

} // namespace vpn