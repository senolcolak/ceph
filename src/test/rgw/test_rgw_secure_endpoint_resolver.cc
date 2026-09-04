// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-

#include <cerrno>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>

#include <boost/asio/ip/address.hpp>
#include <gtest/gtest.h>

#include "rgw_secure_endpoint_resolver.h"

namespace policy = rgw::secure_endpoint;

TEST(RGWSecureEndpoint, validatesHttpsSyntax)
{
  EXPECT_EQ(0, policy::validate_https_endpoint("https://S3.Example.test/path"));
  EXPECT_EQ(0, policy::validate_https_endpoint("https://s3.example.test:443"));
  for (const auto* endpoint : {"http://s3.example.test", "relative/path",
                               "https:///path", "https://user@s3.example.test",
                               "https://s3.example.test/path?x=1",
                               "https://s3.example.test/path#f",
                               "https://s3.example.test:80",
                               "https://s3.example.test:0"}) {
    EXPECT_EQ(-EINVAL, policy::validate_https_endpoint(endpoint));
  }
  EXPECT_EQ(-EINVAL, policy::validate_https_endpoint("https://" + std::string(2048, 'a')));
}

TEST(RGWSecureEndpoint, rejectsSpecialAddresses)
{
  for (const auto* value : {"0.0.0.1", "127.0.0.1", "169.254.169.254",
                            "10.0.0.1", "172.16.0.1", "192.168.0.1",
                            "100.64.0.1", "192.0.2.1", "198.18.0.1",
                            "198.51.100.1", "203.0.113.1", "224.0.0.1",
                            "255.255.255.255"}) {
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(value, ec);
    ASSERT_FALSE(ec);
    EXPECT_TRUE(policy::is_prohibited_address(address)) << value;
  }
  for (const auto* value : {"::", "::1", "100::1", "fe80::1",
                            "fec0::1", "fc00::1", "ff02::1",
                            "2001:2::1", "2001:db8::1", "2002::1",
                            "3fff::1", "::ffff:127.0.0.1"}) {
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(value, ec);
    ASSERT_FALSE(ec);
    EXPECT_TRUE(policy::is_prohibited_address(address)) << value;
  }
}

TEST(RGWSecureEndpoint, rejectsPrivateAndSpecialAddresses)
{
  boost::system::error_code ec;
  auto private_address = boost::asio::ip::make_address("10.0.0.1", ec);
  ASSERT_FALSE(ec);
  EXPECT_TRUE(policy::is_prohibited_address(private_address));
  auto loopback = boost::asio::ip::make_address("127.0.0.1", ec);
  ASSERT_FALSE(ec);
  EXPECT_TRUE(policy::is_prohibited_address(loopback));
  auto cgnat = boost::asio::ip::make_address("100.64.0.1", ec);
  ASSERT_FALSE(ec);
  EXPECT_TRUE(policy::is_prohibited_address(cgnat));
}

TEST(RGWSecureEndpoint, rejectsLiteralPrivateEndpoint)
{
  EXPECT_EQ(-EINVAL, policy::validate_https_endpoint("https://127.0.0.1"));
  EXPECT_EQ(-EINVAL, policy::validate_https_endpoint("https://[::1]"));
}

TEST(RGWSecureEndpoint, exactHostAllowlistDefaultsToDeny)
{
  EXPECT_FALSE(policy::is_endpoint_host_allowed(
    "https://s3.example.test/path", ""));
  EXPECT_TRUE(policy::is_endpoint_host_allowed(
    "https://S3.Example.Test./path",
    " backup.example.test, s3.example.test "));
  EXPECT_FALSE(policy::is_endpoint_host_allowed(
    "https://not-s3.example.test/path", "s3.example.test"));
  EXPECT_FALSE(policy::is_endpoint_host_allowed(
    "https://sub.s3.example.test/path", "s3.example.test"));
  EXPECT_FALSE(policy::is_endpoint_host_allowed(
    "not-a-url", "s3.example.test"));
}

TEST(RGWSecureEndpoint, classifiesSocketAddressesFailClosed)
{
  sockaddr_in ipv4{};
  ipv4.sin_family = AF_INET;
  ASSERT_EQ(1, inet_pton(AF_INET, "93.184.216.34", &ipv4.sin_addr));
  EXPECT_FALSE(policy::is_prohibited_sockaddr(
    reinterpret_cast<const sockaddr*>(&ipv4), sizeof(ipv4)));
  ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.1", &ipv4.sin_addr));
  EXPECT_TRUE(policy::is_prohibited_sockaddr(
    reinterpret_cast<const sockaddr*>(&ipv4), sizeof(ipv4)));

  sockaddr_in6 ipv6{};
  ipv6.sin6_family = AF_INET6;
  ASSERT_EQ(1, inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946",
                         &ipv6.sin6_addr));
  EXPECT_FALSE(policy::is_prohibited_sockaddr(
    reinterpret_cast<const sockaddr*>(&ipv6), sizeof(ipv6)));
  ASSERT_EQ(1, inet_pton(AF_INET6, "::ffff:10.0.0.1", &ipv6.sin6_addr));
  EXPECT_TRUE(policy::is_prohibited_sockaddr(
    reinterpret_cast<const sockaddr*>(&ipv6), sizeof(ipv6)));
  ASSERT_EQ(1, inet_pton(AF_INET6, "::ffff:93.184.216.34", &ipv6.sin6_addr));
  EXPECT_FALSE(policy::is_prohibited_sockaddr(
    reinterpret_cast<const sockaddr*>(&ipv6), sizeof(ipv6)));

  EXPECT_TRUE(policy::is_prohibited_sockaddr(nullptr, 0));
  EXPECT_TRUE(policy::is_prohibited_sockaddr(
    reinterpret_cast<const sockaddr*>(&ipv4), sizeof(ipv4) - 1));
  sockaddr unknown{};
  unknown.sa_family = AF_UNSPEC;
  EXPECT_TRUE(policy::is_prohibited_sockaddr(&unknown, sizeof(unknown)));
}
