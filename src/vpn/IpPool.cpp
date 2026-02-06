#include "vpn/IpPool.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <stdexcept>
#include <sstream>
using namespace std;

namespace vpn {

IpRange::IpRange(const string& start_ip, const string& end_ip,
                 const string& netmask_str, const string& gateway_ip)
    : start(IpPool::ip_to_uint32(start_ip))
    , end(IpPool::ip_to_uint32(end_ip))
    , netmask(IpPool::netmask_to_uint32(netmask_str))
    , gateway(gateway_ip) {
    
    if (start > end) {
        throw runtime_error("start ip cant be bigger than end ip, that doesnt make sense");
    }
}

bool IpRange::contains(uint32_t ip) const {
    return ip >= start && ip <= end;
}

size_t IpRange::size() const {
    return end - start + 1;
}

IpPool::IpPool() : lease_time(86400) {} // keeping ips for 24hrs, seems reasonable

bool IpPool::add_range(const string& start_ip, const string& end_ip,
                       const string& netmask, const string& gateway) {
    lock_guard<mutex> lock(mtx); // gotta lock this so multiple clients dont mess up the ip pool
    
    try {
        ranges.emplace_back(start_ip, end_ip, netmask, gateway);
        return true;
    } catch (const exception&) {
        return false; // something went wrong with the ip range, probably invalid ips
    }
}

void IpPool::clear_ranges() {
    lock_guard<mutex> lock(mtx);
    ranges.clear(); // clearing all the ip ranges
    allocated.clear(); // clearing allocated ips
    clients.clear(); // clearing client to ip mapping
    ips.clear(); // clearing ip to client mapping
}

uint32_t IpPool::find_free_ip() const {
    for (const auto& range : ranges) {
        for (uint32_t ip = range.start; ip <= range.end; ++ip) {
            // skipping first and last ip since those are network and broadcast addresses
            if (ip == range.start || ip == range.end) {
                continue;
            }
            
            if (allocated.find(ip) == allocated.end()) {
                return ip; // found a free ip, lets use this one
            }
        }
    }
    return 0; // couldnt find any free ips, pool is full
}

string IpPool::allocate_ip(const string& client_id) {
    lock_guard<mutex> lock(mtx);
    
    // checking if this client already got an ip from us
    auto existing = clients.find(client_id);
    if (existing != clients.end()) {
        return uint32_to_ip(existing->second); // they already have an ip, just give them the same one
    }
    
    // finding a free ip for the new client
    uint32_t free_ip = find_free_ip();
    if (free_ip == 0) {
        return ""; // no free ips available, pool is maxed out
    }
    
    // allocating this ip to the client
    allocated.insert(free_ip);
    clients[client_id] = free_ip; // mapping client to ip
    ips[free_ip] = client_id;     // mapping ip to client
    
    return uint32_to_ip(free_ip);
}

bool IpPool::release_ip(const string& client_id) {
    lock_guard<mutex> lock(mtx);
    
    auto it = clients.find(client_id);
    if (it == clients.end()) {
        return false; // this client doesnt have an ip from us
    }
    
    uint32_t ip = it->second;
    allocated.erase(ip);    // removing from allocated set
    clients.erase(it);      // removing client to ip mapping
    ips.erase(ip);         // removing ip to client mapping
    
    return true; // ip has been released back to the pool
}

bool IpPool::release_ip_address(const string& ip) {
    lock_guard<mutex> lock(mtx);
    
    uint32_t ip_addr = ip_to_uint32(ip);
    auto it = ips.find(ip_addr);
    if (it == ips.end()) {
        return false; // this ip isnt allocated to anyone
    }
    
    string client_id = it->second;
    allocated.erase(ip_addr);     // removing from allocated set
    clients.erase(client_id);     // removing client to ip mapping 
    ips.erase(it);               // removing ip to client mapping
    
    return true; // released the ip back to pool
}

string IpPool::get_client_ip(const string& client_id) const {
    lock_guard<mutex> lock(mtx);
    
    auto it = clients.find(client_id);
    if (it != clients.end()) {
        return uint32_to_ip(it->second); // found the clients ip
    }
    return ""; // client doesnt have an ip
}

string IpPool::get_ip_client(const string& ip) const {
    lock_guard<mutex> lock(mtx);
    
    uint32_t ip_addr = ip_to_uint32(ip);
    auto it = ips.find(ip_addr);
    if (it != ips.end()) {
        return it->second; // found which client has this ip
    }
    return ""; // no client has this ip
}

bool IpPool::is_ip_allocated(const string& ip) const {
    lock_guard<mutex> lock(mtx);
    uint32_t ip_addr = ip_to_uint32(ip);
    return allocated.find(ip_addr) != allocated.end(); // checking if this ip is taken
}

size_t IpPool::total_ips() const {
    lock_guard<mutex> lock(mtx);
    size_t total = 0;
    for (const auto& range : ranges) {
        total += range.size() - 2; // excluding network and broadcast ips
    }
    return total; // total available ips in all ranges
}

size_t IpPool::allocated_count() const {
    lock_guard<mutex> lock(mtx);
    return allocated.size(); // how many ips are currently taken
}

size_t IpPool::available_count() const {
    return total_ips() - allocated_count(); // simple math to get free ips
}

vector<string> IpPool::get_allocated_ips() const {
    lock_guard<mutex> lock(mtx);
    vector<string> result;
    result.reserve(allocated.size());
    
    for (uint32_t ip : allocated) {
        result.push_back(uint32_to_ip(ip)); // converting all allocated ips to string format
    }
    
    sort(result.begin(), result.end()); // sorting them so they look nice
    return result;
}

string IpPool::get_gateway_for_ip(const string& ip) const {
    lock_guard<mutex> lock(mtx);
    uint32_t ip_addr = ip_to_uint32(ip);
    
    for (const auto& range : ranges) {
        if (range.contains(ip_addr)) {
            return range.gateway; // found which range this ip belongs to
        }
    }
    return ""; // ip doesnt belong to any of our ranges
}

string IpPool::get_netmask_for_ip(const string& ip) const {
    lock_guard<mutex> lock(mtx);
    uint32_t ip_addr = ip_to_uint32(ip);
    
    for (const auto& range : ranges) {
        if (range.contains(ip_addr)) {
            return uint32_to_ip(range.netmask); // found the netmask for this ip
        }
    }
    return ""; // ip doesnt belong to any range
}

uint32_t IpPool::ip_to_uint32(const string& ip) {
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1) {
        throw runtime_error("couldnt convert ip string to number: " + ip);
    }
    return ntohl(sa.sin_addr.s_addr); // converting network byte order to host byte order
}

string IpPool::uint32_to_ip(uint32_t ip) {
    struct sockaddr_in sa;
    sa.sin_addr.s_addr = htonl(ip); // converting host byte order to network byte order
    char buffer[INET_ADDRSTRLEN];
    
    if (inet_ntop(AF_INET, &sa.sin_addr, buffer, sizeof(buffer)) == nullptr) {
        throw runtime_error("couldnt convert ip number to string");
    }
    
    return string(buffer);
}

uint32_t IpPool::netmask_to_uint32(const string& netmask) {
    return ip_to_uint32(netmask); // netmask is just an ip address so we can reuse the same function
}

} // namespace vpn