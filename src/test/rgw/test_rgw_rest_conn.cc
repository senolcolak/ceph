// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_rest_conn.h"

#include "common/ceph_argparse.h"
#include "global/global_init.h"

#include <gtest/gtest.h>

using namespace std;

static constexpr const char* EP1 = "http://127.0.0.1:8000";
static constexpr const char* EP2 = "http://127.0.0.2:8000";
static constexpr const char* PUBLIC_EP = "https://93.184.216.34";

static RGWRESTConn make_conn(const list<string>& endpoints)
{
  return RGWRESTConn(g_ceph_context, "remote-zone", endpoints,
                     RGWAccessKey("access", "secret"), "zonegroup", nullopt);
}

TEST(RGWRESTConn, get_endpoint_uses_resolved_ip)
{
  auto conn = make_conn({EP1});
  ASSERT_EQ(1u, conn.get_endpoint_count());

  RGWEndpoint ep;
  ASSERT_EQ(0, conn.get_endpoint(ep));
  EXPECT_EQ(EP1, ep.get_url());
  EXPECT_EQ("127.0.0.1:8000:127.0.0.1:8000", ep.get_connect_to());
}

TEST(RGWRESTConn, get_endpoint_without_endpoints)
{
  auto conn = make_conn({});

  RGWEndpoint ep;
  EXPECT_EQ(-EINVAL, conn.get_endpoint(ep));
}

TEST(RGWRESTConn, get_endpoint_when_all_ips_are_down)
{
  auto conn = make_conn({EP1, EP2});

  for (size_t i = 0; i < conn.get_endpoint_count(); ++i) {
    RGWEndpoint ep;
    ASSERT_EQ(0, conn.get_endpoint(ep));
    ASSERT_FALSE(ep.get_connect_to().empty());
    conn.set_endpoint_unconnectable(ep);
  }

  RGWEndpoint ep;
  ASSERT_EQ(0, conn.get_endpoint(ep));
  EXPECT_FALSE(ep.get_url().empty());
  // no connect_to hint:
  EXPECT_TRUE(ep.get_connect_to().empty());
}

TEST(RGWRESTConn, require_pinned_preserves_prohibited_address_rejection)
{
  RGWRESTConn conn(g_ceph_context, "remote-zone", {EP1},
                   RGWAccessKey("access", "secret"), "zonegroup", nullopt,
                   PathStyle, RGWEndpointSelectionPolicy::require_pinned);
  RGWEndpoint ep;
  EXPECT_EQ(-EHOSTUNREACH, conn.get_endpoint(ep));
}

TEST(RGWRESTConn, outbound_credentials_are_retained)
{
  RGWOutboundCredentials credentials("temporary-access", "temporary-secret",
                                     std::string("temporary-session"));
  RGWRESTConn conn(g_ceph_context, "remote-zone", {EP1},
                   credentials, "zonegroup", nullopt);

  EXPECT_EQ(credentials.access_key_id, conn.get_credentials().access_key_id);
  EXPECT_EQ(credentials.secret_key, conn.get_credentials().secret_key);
  ASSERT_TRUE(conn.get_credentials().session_token);
  EXPECT_EQ("temporary-session", *conn.get_credentials().session_token);
  EXPECT_EQ(credentials.access_key_id, conn.get_key().id);
  EXPECT_EQ(credentials.secret_key, conn.get_key().key);
}

TEST(RGWRESTConn, temporary_credentials_fail_before_sigv2_send)
{
  const auto previous =
    g_ceph_context->_conf.get_val<int64_t>("rgw_s3_client_max_sig_ver");
  g_ceph_context->_conf.set_val_or_die("rgw_s3_client_max_sig_ver", "2");
  g_ceph_context->_conf.apply_changes(nullptr);

  RGWEndpoint endpoint;
  endpoint.set_url(EP1);
  RGWRESTStreamS3PutObj request(g_ceph_context, "PUT", endpoint, nullptr,
                                nullptr, std::nullopt, PathStyle);
  rgw_obj object;
  object.bucket.name = "bucket";
  object.key.set("object");
  request.send_init(object);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  request.send_ready(
    &dpp, RGWOutboundCredentials{"access", "secret", "session"});
  EXPECT_EQ(-EOPNOTSUPP, request.send(nullptr));

  g_ceph_context->_conf.set_val_or_die(
    "rgw_s3_client_max_sig_ver", std::to_string(previous));
  g_ceph_context->_conf.apply_changes(nullptr);
}

TEST(RGWRESTConn, strict_policy_pins_to_approved_address)
{
  RGWRESTConn conn(g_ceph_context, "remote-zone", {PUBLIC_EP},
                   RGWAccessKey("access", "secret"), "zonegroup", nullopt,
                   PathStyle, RGWEndpointSelectionPolicy::require_pinned,
                   RGWEndpointAddressPolicy::reject_prohibited);
  RGWEndpoint endpoint;
  EXPECT_EQ(0, conn.get_endpoint(endpoint));
  EXPECT_FALSE(endpoint.get_connect_to().empty());
  EXPECT_EQ(RGWEndpointAddressPolicy::reject_prohibited,
            endpoint.get_address_policy());
}

TEST(RGWRESTConn, strict_policy_rejects_prohibited_address)
{
  RGWRESTConn conn(g_ceph_context, "remote-zone", {EP1},
                   RGWAccessKey("access", "secret"), "zonegroup", nullopt,
                   PathStyle, RGWEndpointSelectionPolicy::require_pinned,
                   RGWEndpointAddressPolicy::reject_prohibited);
  RGWEndpoint endpoint;
  EXPECT_EQ(-EHOSTUNREACH, conn.get_endpoint(endpoint));
}

TEST(RGWRESTConn, strict_policy_resolves_and_pins_literal)
{
  g_ceph_context->_conf.set_val_or_die(
    "rgw_rest_conn_connect_to_resolved_ips", "false");
  g_ceph_context->_conf.apply_changes(nullptr);

  RGWRESTConn conn(g_ceph_context, "remote-zone",
                   {PUBLIC_EP},
                   RGWAccessKey("access", "secret"), "zonegroup",
                   std::nullopt, PathStyle,
                   RGWEndpointSelectionPolicy::require_pinned,
                   RGWEndpointAddressPolicy::reject_prohibited);
  RGWEndpoint endpoint;
  EXPECT_EQ(0, conn.get_endpoint(endpoint));
  EXPECT_FALSE(endpoint.get_connect_to().empty());
  EXPECT_FALSE(conn.get_resolved_endpoints().front().resolved_ips.empty());

  g_ceph_context->_conf.set_val_or_die(
    "rgw_rest_conn_connect_to_resolved_ips", "true");
  g_ceph_context->_conf.apply_changes(nullptr);
}

int main(int argc, char** argv)
{
  auto args = argv_to_vec(argc, argv);
  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
                         CODE_ENVIRONMENT_UTILITY,
                         CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);

  cct->_conf.set_val_or_die("rgw_rest_conn_connect_to_resolved_ips", "true");
  // never let a marked-down IP recover while a test is running
  cct->_conf.set_val_or_die("rgw_rest_conn_ip_fail_timeout_secs", "60");
  cct->_conf.apply_changes(nullptr);

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
