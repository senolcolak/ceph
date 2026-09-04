// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include <cerrno>
#include <optional>
#include <string>
#include <utility>

#include <gtest/gtest.h>

#include "rgw_tenant_cloud.h"
#include "rgw_tenant_cloud_credentials.h"

namespace tc = rgw::tenant_cloud;

namespace {

tc::Config valid_config()
{
  tc::Config config;
  config.rule_id = "external-backup";
  config.endpoint = "https://s3.example.test/base";
  config.credential_ref = "vault://backup-main";
  config.target_bucket_arn = "arn:aws:s3:::backup";
  config.source_zone_id = "source-zone-id";
  config.target_zone_id = "zone-id-1";
  config.region = "eu-central-1";
  config.enabled = true;
  return config;
}

TEST(RGWTenantCloud, validates_admission_syntax)
{
  auto config = valid_config();
  std::string error;
  EXPECT_EQ(0, tc::validate(config, &error));

  config.endpoint = "http://s3.example.test";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.endpoint = "https://user@s3.example.test";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.endpoint = "relative/path";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.endpoint = "https:///path";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.endpoint = "https://s3.example.test/path?query";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.endpoint = "https://s3.example.test/path#fragment";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.endpoint = "https://" + std::string(2048, 'a');
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.credential_ref = "vault://project/secret";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.host_style = "virtual";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.region.clear();
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));

  config = valid_config();
  config.target_bucket_arn = "arn:aws:s3:::backup/object";
  EXPECT_EQ(-EINVAL, tc::validate(config, &error));
}

TEST(RGWTenantCloud, encodes_versioned_bucket_attribute)
{
  auto expected = valid_config();
  expected.config_generation = 12;

  tc::Attrs attrs;
  tc::encode_config(expected, &attrs);

  std::optional<tc::Config> actual;
  ASSERT_EQ(0, tc::decode_config(attrs, &actual));
  ASSERT_TRUE(actual);
  EXPECT_EQ(expected.rule_id, actual->rule_id);
  EXPECT_EQ(expected.endpoint, actual->endpoint);
  EXPECT_EQ(expected.credential_ref, actual->credential_ref);
  EXPECT_EQ(expected.target_bucket_arn, actual->target_bucket_arn);
  EXPECT_EQ(expected.source_zone_id, actual->source_zone_id);
  EXPECT_EQ(expected.target_zone_id, actual->target_zone_id);
  EXPECT_EQ(expected.region, actual->region);
  EXPECT_EQ(expected.host_style, actual->host_style);
  EXPECT_EQ(expected.config_generation, actual->config_generation);
  EXPECT_EQ(expected.enabled, actual->enabled);
}

TEST(RGWTenantCloud, rejects_corrupt_bucket_attribute)
{
  tc::Attrs attrs;
  attrs[tc::config_attr].append("not-an-encoded-config");

  std::optional<tc::Config> config;
  EXPECT_EQ(-EIO, tc::decode_config(attrs, &config));
  EXPECT_FALSE(config);
}

TEST(RGWTenantCloud, rejects_null_decode_destination)
{
  tc::Attrs attrs;
  EXPECT_EQ(-EINVAL, tc::decode_config(attrs, nullptr));
}

TEST(RGWTenantCloud, decodes_previous_poc_attribute_layout)
{
  const auto expected = valid_config();
  bufferlist encoded;
  ENCODE_START(2, 1, encoded);
  encode(expected.rule_id, encoded);
  encode(expected.endpoint, encoded);
  encode(expected.credential_ref, encoded);
  encode(expected.target_bucket_arn, encoded);
  encode(expected.source_zone_id, encoded);
  encode(expected.target_zone_id, encoded);
  encode(expected.region, encoded);
  encode(expected.host_style, encoded);
  encode(uint64_t{9}, encoded);
  encode(uint64_t{4}, encoded);
  encode(true, encoded);
  encode(false, encoded);
  ENCODE_FINISH(encoded);

  tc::Attrs attrs;
  attrs[tc::config_attr] = std::move(encoded);
  std::optional<tc::Config> actual;
  ASSERT_EQ(0, tc::decode_config(attrs, &actual));
  ASSERT_TRUE(actual);
  EXPECT_EQ(9u, actual->config_generation);
  EXPECT_TRUE(actual->enabled);
  EXPECT_EQ(expected.source_zone_id, actual->source_zone_id);
}

TEST(RGWTenantCloud, rejects_unassigned_stored_generation)
{
  auto invalid = valid_config();
  tc::Attrs attrs;
  tc::encode_config(invalid, &attrs);

  std::optional<tc::Config> config;
  EXPECT_EQ(-EIO, tc::decode_config(attrs, &config));
  EXPECT_FALSE(config);
}

TEST(RGWTenantCloud, assignsStableGenerationToImmutableConfig)
{
  auto previous = valid_config();
  previous.config_generation = 7;

  auto next = previous;
  ASSERT_EQ(0, tc::advance_generation(previous, 7, &next));
  EXPECT_EQ(7, next.config_generation);
  EXPECT_EQ(-EINVAL, tc::advance_generation(previous, 7, nullptr));

  next.credential_ref = "vault://backup-rotated";
  EXPECT_EQ(-EOPNOTSUPP, tc::advance_generation(previous, 7, &next));

  next = valid_config();
  EXPECT_EQ(0, tc::advance_generation(std::nullopt, 7, &next));
  EXPECT_EQ(8, next.config_generation);
}

TEST(RGWTenantCloud, preservesGenerationAcrossDeleteAndRecreate)
{
  tc::Attrs attrs;
  tc::encode_epoch(12, &attrs);

  uint64_t epoch = 0;
  ASSERT_EQ(0, tc::decode_epoch(attrs, &epoch));
  EXPECT_EQ(12u, epoch);

  auto recreated = valid_config();
  ASSERT_EQ(0, tc::advance_generation(std::nullopt, epoch, &recreated));
  EXPECT_EQ(13u, recreated.config_generation);
}

TEST(RGWTenantCloud, parses_versioned_credentials)
{
  bufferlist encoded;
  encoded.append(R"({"data":{"data":{"version":1,"access_key_id":"AKIA","secret_key":"secret","session_token":"token","expires_at":1700000000}}})");

  tc::Credentials credentials;
  ASSERT_EQ(0, tc::parse_vault_credentials(encoded, &credentials));
  EXPECT_EQ(1u, credentials.version);
  EXPECT_EQ("AKIA", credentials.access_key_id);
  EXPECT_EQ("secret", credentials.secret_key);
  ASSERT_TRUE(credentials.session_token);
  EXPECT_EQ("token", *credentials.session_token);
  ASSERT_TRUE(credentials.expires_at);
  EXPECT_EQ(1700000000u, *credentials.expires_at);
}

TEST(RGWTenantCloud, rejects_invalid_versioned_credentials)
{
  for (const auto json : {
         R"({"version":2,"access_key_id":"AKIA","secret_key":"secret"})",
         R"({"version":1,"access_key_id":"","secret_key":"secret"})",
         R"({"version":1,"access_key_id":"AKIA","secret_key":""})",
         R"({"version":1,"access_key_id":"AKIA","secret_key":"secret","session_token":""})",
         R"({"version":1,"access_key_id":"AKIA"})",
         "not-json"}) {
    bufferlist encoded;
    encoded.append("{\"data\":{\"data\":");
    encoded.append(json);
    encoded.append("}}");
    tc::Credentials credentials;
    EXPECT_EQ(-EINVAL, tc::parse_vault_credentials(encoded, &credentials));
  }
}

TEST(RGWTenantCloud, rejects_empty_or_missing_credential_output)
{
  bufferlist empty;
  tc::Credentials credentials;
  EXPECT_EQ(-EINVAL, tc::parse_vault_credentials(empty, &credentials));
  EXPECT_EQ(-EINVAL, tc::parse_vault_credentials(empty, nullptr));

  bufferlist missing_envelope;
  missing_envelope.append(
    R"({"version":1,"access_key_id":"AKIA","secret_key":"secret"})");
  EXPECT_EQ(-EINVAL,
            tc::parse_vault_credentials(missing_envelope, &credentials));
}

} // anonymous namespace
