// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "rgw_obj_types.h"
#include "rgw_sync_module.h"
#include "rgw_sync_s3_transfer.h"
#include "rgw_tenant_cloud.h"
#include "rgw_tenant_cloud_credentials.h"
#include "rgw_user_types.h"

struct RGWDataSyncCtx;

namespace rgw::tenant_cloud {

struct TargetContext {
  rgw_owner owner;
  std::string bucket_instance_id;
  uint64_t config_generation{0};
  std::string destination_bucket;
  std::string source_zone_id;
  std::string endpoint;
  std::string credential_ref;
  std::string target_zone_id;
  std::string region;
  std::string host_style;
  std::shared_ptr<rgw::sync::s3::Target> target;
};

using TargetContextRef = std::shared_ptr<const TargetContext>;

class TargetContextProvider {
public:
  virtual ~TargetContextProvider() = default;

  // Inputs are values so that implementations can safely move them into a
  // resolver coroutine. Implementations must copy any dependency needed across
  // a yield, must publish the result exactly once and only on success, and must
  // not retain result or dpp after the returned coroutine completes. The
  // provider is trusted to construct target from the identity stored beside it.
  virtual RGWCoroutine* resolve(const DoutPrefixProvider* dpp,
                                RGWDataSyncCtx* sync, rgw_owner owner,
                                std::string bucket_instance_id, Config config,
                                TargetContextRef* result) = 0;
};

std::shared_ptr<TargetContextProvider> make_resolving_target_context_provider(
  std::shared_ptr<CredentialResolver> resolver);

int target_bucket_name(const Config& config, std::string* bucket);
int validate_target_context(const TargetContext& context,
                            const rgw_owner& owner,
                            const std::string& bucket_instance_id,
                            const Config& config);
int build_target_context(CephContext* cct,
                         const rgw_owner& owner,
                         const std::string& bucket_instance_id,
                         const std::string& source_zonegroup_id,
                         const Config& config,
                         const Credentials& credentials,
                         TargetContextRef* result);
int make_delete_path(const TargetContext& context, const rgw_obj_key& key,
                     std::string* path);
int make_put_objects(const TargetContext& context,
                     const rgw_bucket& source_bucket,
                     const rgw_obj_key& key, rgw_obj* source,
                     rgw_obj* destination);
int decode_source_properties(const std::map<std::string, bufferlist>& attrs,
                             rgw::sync::s3::SourceProperties* properties);
void copy_safe_headers(const DoutPrefixProvider* dpp,
                       const rgw_rest_obj& source,
                       std::map<std::string, std::string>* destination);
std::unique_ptr<RGWDataSyncModule> make_data_sync_module(
  std::shared_ptr<TargetContextProvider> provider);

} // namespace rgw::tenant_cloud

// Tenant-cloud data-sync module registration.
class RGWTenantCloudSyncModule : public RGWSyncModule {
public:
  bool supports_data_export() override
  {
    return false;
  }

  int create_instance(const DoutPrefixProvider* dpp, CephContext* cct,
                      const JSONFormattable& config,
                      RGWSyncModuleInstanceRef* instance) override;
};
