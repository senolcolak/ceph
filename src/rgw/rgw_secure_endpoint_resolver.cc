// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_secure_endpoint_resolver.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <string>

#include <boost/url/parse.hpp>

namespace rgw::secure_endpoint {
namespace {

std::string canonical_host(std::string_view host)
{
  while (!host.empty() && std::isspace(static_cast<unsigned char>(host.front()))) {
    host.remove_prefix(1);
  }
  while (!host.empty() && std::isspace(static_cast<unsigned char>(host.back()))) {
    host.remove_suffix(1);
  }
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
    host.remove_prefix(1);
    host.remove_suffix(1);
  }
  if (!host.empty() && host.back() == '.') {
    host.remove_suffix(1);
  }
  std::string result(host);
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return result;
}

bool in_range(uint32_t value, uint32_t first, uint32_t last)
{
  return value >= first && value <= last;
}

bool prohibited_v4(const boost::asio::ip::address_v4& address)
{
  const auto bytes = address.to_bytes();
  const uint32_t value = (uint32_t(bytes[0]) << 24) |
                         (uint32_t(bytes[1]) << 16) |
                         (uint32_t(bytes[2]) << 8) | bytes[3];
  if (bytes[0] == 0 || bytes[0] == 127 ||
      in_range(value, 0xe0000000, 0xffffffff) ||
      in_range(value, 0xa9fe0000, 0xa9feffff) ||
      in_range(value, 0xc0000000, 0xc00000ff) ||
      in_range(value, 0xc0000200, 0xc00002ff) ||
      in_range(value, 0xc0586300, 0xc05863ff) ||
      in_range(value, 0xc6120000, 0xc613ffff) ||
      in_range(value, 0xc6336400, 0xc63364ff) ||
      in_range(value, 0xcb007100, 0xcb0071ff) ||
      in_range(value, 0x64400000, 0x647fffff)) {
    return true;
  }
  if (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
      (bytes[0] == 192 && bytes[1] == 168)) {
    return true;
  }
  if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) {
    return true;
  }
  return false;
}

bool prohibited_v6(const boost::asio::ip::address_v6& address)
{
  if (address.is_unspecified() || address.is_loopback() ||
      address.is_link_local() || address.is_multicast()) {
    return true;
  }
  const auto bytes = address.to_bytes();
  // Public IPv6 unicast is allocated from 2000::/3. Exclude the special-use
  // subranges within it that must not be reached by tenant-controlled URLs.
  if ((bytes[0] & 0xe0) != 0x20 ||
      (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 0x02) ||
      (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d &&
       bytes[3] == 0xb8) ||
      (bytes[0] == 0x20 && bytes[1] == 0x02) ||
      (bytes[0] == 0x3f && bytes[1] == 0xff &&
       (bytes[2] & 0xf0) == 0)) {
    return true;
  }
  return false;
}

} // anonymous namespace

int validate_https_endpoint(std::string_view endpoint)
{
  auto parsed = boost::urls::parse_uri(endpoint);
  if (!parsed || parsed->scheme() != "https" ||
      !parsed->has_authority() || parsed->host().empty() ||
      parsed->has_userinfo() || parsed->has_query() ||
      parsed->has_fragment() || endpoint.size() > 2048) {
    return -EINVAL;
  }

  if (parsed->has_port()) {
    const auto port_text = parsed->port();
    unsigned value = 0;
    const auto result = std::from_chars(port_text.data(),
                                        port_text.data() + port_text.size(),
                                        value);
    if (result.ec != std::errc{} || result.ptr != port_text.data() + port_text.size() ||
        value != 443) {
      return -EINVAL;
    }
  }

  std::string host(parsed->host());
  if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
    host = host.substr(1, host.size() - 2);
  }
  boost::system::error_code ec;
  const auto address = boost::asio::ip::make_address(host, ec);
  if (!ec && is_prohibited_address(address)) {
    return -EINVAL;
  }

  return 0;
}

bool is_endpoint_host_allowed(std::string_view endpoint,
                              std::string_view allowlist)
{
  const auto parsed = boost::urls::parse_uri(endpoint);
  if (!parsed || parsed->host().empty()) {
    return false;
  }
  const auto endpoint_host = canonical_host(parsed->host());
  while (!allowlist.empty()) {
    const auto separator = allowlist.find(',');
    const auto candidate = canonical_host(allowlist.substr(0, separator));
    if (!candidate.empty() && candidate == endpoint_host) {
      return true;
    }
    if (separator == std::string_view::npos) {
      break;
    }
    allowlist.remove_prefix(separator + 1);
  }
  return false;
}

bool is_prohibited_address(const boost::asio::ip::address& address)
{
  if (address.is_v4()) {
    return prohibited_v4(address.to_v4());
  }
  const auto v6 = address.to_v6();
  if (v6.is_v4_mapped()) {
    const auto bytes = v6.to_bytes();
    boost::asio::ip::address_v4::bytes_type v4bytes{{bytes[12], bytes[13],
                                                      bytes[14], bytes[15]}};
    return prohibited_v4(boost::asio::ip::address_v4(v4bytes));
  }
  return prohibited_v6(v6);
}

bool is_prohibited_sockaddr(const sockaddr* address, socklen_t length)
{
  if (!address) {
    return true;
  }
  if (address->sa_family == AF_INET) {
    if (length < sizeof(sockaddr_in)) {
      return true;
    }
    sockaddr_in value{};
    std::memcpy(&value, address, sizeof(value));
    boost::asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), &value.sin_addr, bytes.size());
    return is_prohibited_address(boost::asio::ip::address_v4(bytes));
  }
  if (address->sa_family == AF_INET6) {
    if (length < sizeof(sockaddr_in6)) {
      return true;
    }
    sockaddr_in6 value{};
    std::memcpy(&value, address, sizeof(value));
    boost::asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), &value.sin6_addr, bytes.size());
    return is_prohibited_address(boost::asio::ip::address_v6(bytes));
  }
  return true;
}

} // namespace rgw::secure_endpoint
