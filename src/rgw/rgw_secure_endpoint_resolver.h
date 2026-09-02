// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <string_view>

#include <boost/asio/ip/address.hpp>

namespace rgw::secure_endpoint {

// Validate the syntax accepted by the initial tenant-cloud path-style client.
// This is an admission check only; DNS answers must be checked again at
// connection time by the eventual asynchronous resolver.
int validate_https_endpoint(std::string_view endpoint);

// Returns true for addresses that must not be used by a tenant-controlled
// outbound connection under the default policy. IPv4-mapped IPv6 addresses
// are classified as their mapped IPv4 address.
bool is_prohibited_address(const boost::asio::ip::address& address);

} // namespace rgw::secure_endpoint
