// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "include/buffer.h"
#include "include/encoding.h"

namespace rgw::tenant_cloud {

inline constexpr auto config_attr = "user.rgw.tenant-cloud";

// External destination data is deliberately kept out of rgw_sync_policy_info.
// The policy points at an internal mirrored bucket; this attribute tells the
// tenant-cloud data-sync module where that bucket is exported.
struct Config {
  std::string rule_id;
  std::string endpoint;
  std::string credential_ref;
  std::string target_bucket_arn;
  std::string source_zone_id;
  std::string target_zone_id;
  std::string region;
  std::string host_style{"path"};
  uint64_t config_generation{0};
  bool enabled{false};

  void encode(bufferlist& bl) const
  {
    ENCODE_START(3, 1, bl);
    encode(rule_id, bl);
    encode(endpoint, bl);
    encode(credential_ref, bl);
    encode(target_bucket_arn, bl);
    encode(source_zone_id, bl);
    encode(target_zone_id, bl);
    encode(region, bl);
    encode(host_style, bl);
    encode(config_generation, bl);
    encode(enabled, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::const_iterator& p)
  {
    DECODE_START(3, p);
    decode(rule_id, p);
    decode(endpoint, p);
    decode(credential_ref, p);
    decode(target_bucket_arn, p);
    if (struct_v >= 2) {
      decode(source_zone_id, p);
    }
    decode(target_zone_id, p);
    decode(region, p);
    decode(host_style, p);
    decode(config_generation, p);
    if (struct_v < 3) {
      uint64_t discarded_backfill_epoch;
      decode(discarded_backfill_epoch, p);
    }
    decode(enabled, p);
    if (struct_v < 3) {
      bool discarded_replicate_delete_markers;
      decode(discarded_replicate_delete_markers, p);
    }
    DECODE_FINISH(p);
  }
};
WRITE_CLASS_ENCODER(Config)

using Attrs = std::map<std::string, bufferlist>;

struct Credentials {
  uint32_t version{0};
  std::string access_key_id;
  std::string secret_key;
  std::optional<std::string> session_token;
  std::optional<uint64_t> expires_at;
};

// These checks are admission checks only. Runtime DNS/IP policy and
// connection-time address pinning belong in the secure endpoint resolver.
int validate(const Config& config, std::string* error);

int decode_config(const Attrs& attrs, std::optional<Config>* config);
void encode_config(const Config& config, Attrs* attrs);

// Assign the generation immediately before the atomic bucket metadata write.
int advance_generation(const std::optional<Config>& previous, Config* next);

} // namespace rgw::tenant_cloud
