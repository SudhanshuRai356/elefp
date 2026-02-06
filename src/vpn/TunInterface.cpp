#include "vpn/TunInterface.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iostream>
using namespace std;

namespace vpn {

TunInterface::TunInterface() : fd(-1), is_up(false) {}

TunInterface::~TunInterface() {
    close();
}

TunInterface::TunInterface(TunInterface&& other) noexcept 
    : fd(other.fd), name(move(other.name)),
      ip(move(other.ip)), mask(move(other.mask)),
      is_up(other.is_up) {
    other.fd = -1;     // taking over the file descriptor
    other.is_up = false;
}

TunInterface& TunInterface::operator=(TunInterface&& other) noexcept {
    if (this != &other) {
        close(); // cleaning up current interface first
        fd = other.fd;
        name = move(other.name);
        ip = move(other.ip);
        mask = move(other.mask);
        is_up = other.is_up;
        
        other.fd = -1;     // taking ownership
        other.is_up = false;
    }
    return *this;
}

bool TunInterface::open(const string& interface_name) {
    if (is_up) {
        return true; // already got a tun interface running
    }
    
    // opening the tun device
    fd = ::open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return false; // couldnt open tun device, probably need root
    }
    
    // setting up the interface configuration
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // tun device without packet info headers
    
    if (!interface_name.empty()) {
        strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
        name = interface_name;
    } else {
        name = get_next_available_name(); // finding an available tun name
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    }
    
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        ::close(fd);
        fd = -1;
        return false; // couldnt create the tun interface
    }
    
    // getting the actual name the kernel gave us
    name = ifr.ifr_name;
    is_up = true;
    
    return true; // tun interface is ready to use
}

void TunInterface::close() {
    if (fd >= 0) {
        ::close(fd); // closing the tun device
        fd = -1;
    }
    is_up = false;  // interface is down now
    name.clear();
    ip.clear();
    mask.clear();
}

bool TunInterface::configure(const string& ip_addr, const string& netmask, int mtu) {
    if (!is_up) {
        return false; // cant configure an interface thats not open
    }
    
    ip = ip_addr;
    mask = netmask;
    
    // creating a socket to configure the interface
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return false; // couldnt create socket for configuration
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    
    // setting up the ip address
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip_addr.c_str(), &addr->sin_addr);
    
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        ::close(sock);
        return false; // couldnt set ip address
    }
    
    // setting up the netmask
    inet_pton(AF_INET, netmask.c_str(), &addr->sin_addr);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        ::close(sock);
        return false; // couldnt set netmask
    }
    
    // setting the mtu size
    ifr.ifr_mtu = mtu;
    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        ::close(sock);
        return false; // couldnt set mtu
    }
    
    // bringing the interface up and running
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        ::close(sock);
        return false; // couldnt bring interface up
    }
    
    ::close(sock);
    return true; // tun interface is configured and ready
}

ssize_t TunInterface::read_packet(vector<uint8_t>& packet) {
    if (!is_up) {
        return -1; // cant read from closed interface
    }
    
    packet.resize(2048); // making room for a packet, 2kb should be enough
    ssize_t len = read(fd, packet.data(), packet.size());
    if (len > 0) {
        packet.resize(len); // trimming packet to actual size
    }
    return len; // how many bytes we read
}

ssize_t TunInterface::write_packet(const vector<uint8_t>& packet) {
    if (!is_up) {
        return -1; // cant write to closed interface
    }
    
    return write(fd, packet.data(), packet.size()); // writing packet to tun device
}

string TunInterface::get_next_available_name(const string& prefix) {
    for (int i = 0; i < 100; ++i) {
        string name = prefix + to_string(i); // trying tun0, tun1, tun2, etc
        
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue; // couldnt create socket, try next number
        
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        
        // checking if this interface name already exists
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            ::close(sock);
            return name; // this name is free, lets use it
        }
        
        ::close(sock);
    }
    
    return prefix + "0"; // if all else fails, just use tun0
}

bool TunInterface::add_route(const string& dest, const string& gateway, const string& interface) {
    ostringstream cmd;
    cmd << "ip route add " << dest << " via " << gateway << " dev " << interface;
    return system(cmd.str().c_str()) == 0; // using ip command to add route
}

bool TunInterface::delete_route(const string& dest, const string& gateway, const string& interface) {
    ostringstream cmd;
    cmd << "ip route del " << dest << " via " << gateway << " dev " << interface;
    return system(cmd.str().c_str()) == 0; // using ip command to delete route
}

} // namespace vpn