// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <string_view>
#include <sys/socket.h>

#include <boost/asio/ip/address.hpp>

namespace rgw::secure_endpoint {

int validate_https_endpoint(std::string_view endpoint);

bool is_endpoint_host_allowed(std::string_view endpoint,
                              std::string_view allowlist);

// Returns true for addresses that must not be used by a tenant-controlled
// outbound connection under the default policy. IPv4-mapped IPv6 addresses
// are classified as their mapped IPv4 address.
bool is_prohibited_address(const boost::asio::ip::address& address);

// Fail closed when libcurl presents an unsupported or malformed address.
bool is_prohibited_sockaddr(const sockaddr* address, socklen_t length);

} // namespace rgw::secure_endpoint
