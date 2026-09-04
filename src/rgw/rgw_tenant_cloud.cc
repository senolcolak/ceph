// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_tenant_cloud.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <limits>
#include <string_view>

#include "rgw_arn.h"
#include "rgw_secure_endpoint_resolver.h"
#include "common/ceph_context.h"

namespace rgw::tenant_cloud {
namespace {

bool valid_credential_name(std::string_view name)
{
  if (name.empty() || name.size() > 255 || name == "." || name == "..") {
    return false;
  }
  return std::all_of(name.begin(), name.end(), [](unsigned char c) {
    return std::isalnum(c) || c == '-' || c == '_' || c == '.';
  });
}

} // anonymous namespace

int validate(const Config& config, std::string* error)
{
  const auto fail = [error](std::string message) {
    if (error) {
      *error = std::move(message);
    }
    return -EINVAL;
  };

  if (config.rule_id.empty()) {
    return fail("external replication requires a rule ID");
  }
  auto target = ARN::parse(config.target_bucket_arn);
  if (!target || target->service != rgw::Service::s3 ||
      !target->region.empty() || !target->account.empty() ||
      target->resource.empty() ||
      target->resource.find_first_of("/:") != std::string::npos) {
    return fail("external replication requires an S3 bucket ARN");
  }
  if (config.target_zone_id.empty()) {
    return fail("external replication requires one tenant-cloud destination zone");
  }
  if (config.source_zone_id.empty()) {
    return fail("external replication requires one source zone");
  }
  if (config.region.empty()) {
    return fail("external replication requires a destination signing region");
  }
  if (config.host_style != "path") {
    return fail("tenant-cloud replication supports path HostStyle only");
  }
  if (config.endpoint.size() > 2048) {
    return fail("external replication endpoint is too long");
  }

  if (rgw::secure_endpoint::validate_https_endpoint(config.endpoint) != 0) {
    return fail("external replication endpoint must be an absolute HTTPS URL without userinfo, query, or fragment");
  }

  constexpr std::string_view prefix = "vault://";
  if (!std::string_view(config.credential_ref).starts_with(prefix) ||
      !valid_credential_name(
        std::string_view(config.credential_ref).substr(prefix.size()))) {
    return fail("credential reference must be vault:// followed by a logical name");
  }

  return 0;
}

int validate_endpoint_policy(const CephContext* cct, const Config& config,
                             std::string* error)
{
  if (!cct) {
    return -EINVAL;
  }
  const auto& allowlist = cct->_conf.get_val<std::string>(
    "rgw_tenant_cloud_endpoint_allowlist");
  if (!rgw::secure_endpoint::is_endpoint_host_allowed(config.endpoint,
                                                        allowlist)) {
    if (error) {
      *error = "external replication endpoint host is not allowed";
    }
    return -EINVAL;
  }
  return 0;
}

int decode_config(const Attrs& attrs, std::optional<Config>* config)
{
  if (!config) {
    return -EINVAL;
  }
  config->reset();
  auto i = attrs.find(config_attr);
  if (i == attrs.end()) {
    return 0;
  }

  try {
    auto p = i->second.cbegin();
    Config decoded;
    decode(decoded, p);
    if (decoded.config_generation == 0) {
      return -EIO;
    }
    *config = std::move(decoded);
  } catch (const buffer::error&) {
    return -EIO;
  }
  return 0;
}

int decode_epoch(const Attrs& attrs, uint64_t* epoch)
{
  if (!epoch) {
    return -EINVAL;
  }
  *epoch = 0;
  const auto i = attrs.find(epoch_attr);
  if (i == attrs.end()) {
    return 0;
  }
  try {
    auto p = i->second.cbegin();
    ceph_le64 encoded_epoch;
    ceph::decode_raw(encoded_epoch, p);
    *epoch = encoded_epoch;
  } catch (const buffer::error&) {
    return -EIO;
  }
  return 0;
}

void encode_epoch(uint64_t epoch, Attrs* attrs)
{
  if (!attrs) {
    return;
  }
  bufferlist bl;
  ceph_le64 encoded_epoch;
  encoded_epoch = epoch;
  ceph::encode_raw(encoded_epoch, bl);
  (*attrs)[epoch_attr] = std::move(bl);
}

void encode_config(const Config& config, Attrs* attrs)
{
  bufferlist bl;
  encode(config, bl);
  (*attrs)[config_attr] = std::move(bl);
}

int advance_generation(const std::optional<Config>& previous, uint64_t epoch,
                       Config* next)
{
  if (!next) {
    return -EINVAL;
  }
  if (!previous) {
    if (epoch == std::numeric_limits<uint64_t>::max()) {
      return -EOVERFLOW;
    }
    next->config_generation = epoch + 1;
    return 0;
  }
  auto expected = *previous;
  expected.config_generation = 0;
  auto requested = *next;
  requested.config_generation = 0;
  if (expected != requested) {
    return -EOPNOTSUPP;
  }
  next->config_generation = previous->config_generation;
  return 0;
}

} // namespace rgw::tenant_cloud
