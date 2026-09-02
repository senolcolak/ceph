// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_sync_module_tenant_cloud.h"
#include "rgw_tenant_cloud_credentials.h"

#include <cerrno>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "rgw_bucket_sync.h"
#include "rgw_data_sync.h"
#include "rgw_arn.h"
#include "rgw_tenant_cloud.h"
#include "services/svc_zone.h"

#include <boost/asio/yield.hpp>

#define dout_subsys ceph_subsys_rgw

namespace {

bool pipe_matches_source(const rgw_bucket_sync_pipe& pipe)
{
  return pipe.info.source_bs.bucket == pipe.source_bucket_info.bucket &&
         pipe.info.dest_bucket == pipe.source_bucket_info.bucket;
}

class RGWTenantCloudResolvedProvider final
  : public rgw::tenant_cloud::TargetContextProvider {
  std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver;

  class ResolveCR final : public RGWCoroutine {
    RGWDataSyncCtx* sync;
    std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver;
    rgw_owner owner;
    std::string bucket_instance_id;
    rgw::tenant_cloud::Config config;
    rgw::tenant_cloud::TargetContextRef* result;
    rgw::tenant_cloud::Credentials credentials;
    std::unique_ptr<RGWCoroutine> operation;

  public:
    ResolveCR(RGWDataSyncCtx* sync,
              std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver,
              rgw_owner owner, std::string bucket_instance_id,
              rgw::tenant_cloud::Config config,
              rgw::tenant_cloud::TargetContextRef* result)
      : RGWCoroutine(sync->cct), sync(sync), resolver(std::move(resolver)),
        owner(std::move(owner)),
        bucket_instance_id(std::move(bucket_instance_id)),
        config(std::move(config)), result(result) {}

    int operate(const DoutPrefixProvider*) override
    {
      reenter(this) {
        if (!resolver || !result) {
          return set_cr_error(-EINVAL);
        }
        operation.reset(resolver->resolve(owner, config, &credentials));
        if (!operation) {
          return set_cr_error(-EINVAL);
        }
        yield call(operation.release());
        if (retcode < 0) {
          return set_cr_error(retcode);
        }
        return rgw::tenant_cloud::build_target_context(
          sync->cct, owner, bucket_instance_id,
          sync->env->svc->zone->get_zonegroup().get_id(), config, credentials,
          result) < 0
          ? set_cr_error(-EIO) : set_cr_done();
      }
      return 0;
    }
  };

public:
  explicit RGWTenantCloudResolvedProvider(
    std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver)
    : resolver(std::move(resolver)) {}

  RGWCoroutine* resolve(const DoutPrefixProvider* dpp, RGWDataSyncCtx* sync,
                        rgw_owner owner, std::string bucket_instance_id,
                        rgw::tenant_cloud::Config config,
                        rgw::tenant_cloud::TargetContextRef* result) override
  {
    return new ResolveCR(sync, resolver, std::move(owner),
                         std::move(bucket_instance_id), std::move(config), result);
  }
};

class RGWTenantCloudUnimplementedCR : public RGWCoroutine {
  std::string_view operation;

public:
  RGWTenantCloudUnimplementedCR(CephContext* cct, std::string_view operation)
    : RGWCoroutine(cct), operation(operation) {}

  int operate(const DoutPrefixProvider* dpp) override
  {
    ldpp_dout(dpp, 0)
      << "ERROR: tenant-cloud PoC does not support " << operation << dendl;

    // EIO is not one of RGWBucketSyncSingleEntryCR's ignored outcomes. This
    // keeps retry ownership in Ceph and prevents marker advancement.
    return set_cr_error(-EIO);
  }
};

class RGWTenantCloudDeleteCR final : public RGWCoroutine {
  RGWDataSyncCtx* sync;
  std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider;
  rgw_owner owner;
  std::string bucket_instance_id;
  rgw_obj_key key;
  std::optional<rgw::tenant_cloud::Config> config;
  int config_result;
  bool pipe_matches;
  rgw::tenant_cloud::TargetContextRef context;
  std::unique_ptr<RGWCoroutine> resolver;
  std::string path;

public:
  RGWTenantCloudDeleteCR(
    RGWDataSyncCtx* sync, const rgw_bucket_sync_pipe& sync_pipe,
    const rgw_obj_key& key,
    std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider)
    : RGWCoroutine(sync->cct),
      sync(sync),
      provider(std::move(provider)),
      owner(sync_pipe.source_bucket_info.owner),
      bucket_instance_id(sync_pipe.source_bucket_info.bucket.bucket_id),
      key(key),
      config(),
      config_result(rgw::tenant_cloud::decode_config(
        sync_pipe.source_bucket_attrs, &config)),
      pipe_matches(pipe_matches_source(sync_pipe))
  {
    if (config_result == 0 && config) {
      std::string error;
      config_result = rgw::tenant_cloud::validate(*config, &error);
      pipe_matches = pipe_matches && config->enabled;
    }
  }

  int operate(const DoutPrefixProvider* dpp) override
  {
    reenter(this) {
      if (config_result < 0 || !config || !pipe_matches || !provider ||
          sync->source_zone.id != config->source_zone_id ||
          key.need_to_encode_instance() ||
          !key.ns.empty()) {
        return set_cr_error(-EIO);
      }

      context.reset();
      resolver.reset(provider->resolve(dpp, sync, owner, bucket_instance_id,
                                       *config, &context));
      if (!resolver) {
        return set_cr_error(-EIO);
      }
      yield call(resolver.release());
      if (retcode < 0) {
        return set_cr_error(
          rgw::sync::s3::normalize_write_result(retcode));
      }
      if (!context || !context->target ||
          rgw::tenant_cloud::validate_target_context(
            *context, owner, bucket_instance_id, *config) < 0 ||
          rgw::tenant_cloud::make_delete_path(*context, key, &path) < 0) {
        return set_cr_error(-EIO);
      }

      yield call(rgw::sync::s3::delete_object(
        cct, context->target, sync->env->http_manager, path));
      retcode = rgw::sync::s3::normalize_write_result(retcode);
      if (retcode < 0) {
        return set_cr_error(retcode);
      }
      return set_cr_done();
    }
    return 0;
  }
};

class RGWTenantCloudPutCBCR final : public RGWStatRemoteObjCBCR {
  std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider;
  rgw_owner owner;
  std::string bucket_instance_id;
  rgw::tenant_cloud::Config config;
  rgw::tenant_cloud::TargetContextRef context;
  std::unique_ptr<RGWCoroutine> resolver;
  RGWRESTConn* source_conn{nullptr};
  rgw_obj source_obj;
  rgw_obj destination_obj;
  rgw::sync::s3::SourceProperties properties;
  std::shared_ptr<RGWStreamReadHTTPResourceCRF> reader;
  std::shared_ptr<RGWStreamWriteHTTPResourceCRF> writer;

public:
  RGWTenantCloudPutCBCR(
    RGWDataSyncCtx* sync, rgw_bucket_sync_pipe& sync_pipe, rgw_obj_key& key,
    std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider,
    rgw::tenant_cloud::Config config)
    : RGWStatRemoteObjCBCR(sync, sync_pipe.info.source_bs.bucket, key),
      provider(std::move(provider)),
      owner(sync_pipe.source_bucket_info.owner),
      bucket_instance_id(sync_pipe.source_bucket_info.bucket.bucket_id),
      config(std::move(config)) {}

  int operate(const DoutPrefixProvider* dpp) override
  {
    reenter(this) {
      if (!provider) {
        return set_cr_error(-EIO);
      }

      context.reset();
      resolver.reset(provider->resolve(dpp, sc, owner, bucket_instance_id,
                                       config, &context));
      if (!resolver) {
        return set_cr_error(-EIO);
      }
      yield call(resolver.release());
      if (retcode < 0) {
        return set_cr_error(rgw::sync::s3::normalize_write_result(retcode));
      }
      if (!context || rgw::tenant_cloud::validate_target_context(
                        *context, owner, bucket_instance_id, config) < 0 ||
          rgw::tenant_cloud::make_put_objects(
            *context, src_bucket, key, &source_obj, &destination_obj) < 0) {
        return set_cr_error(-EIO);
      }

      if (rgw::tenant_cloud::decode_source_properties(
            attrs, &properties) < 0) {
        return set_cr_error(-EIO);
      }
      properties.mtime = mtime;
      properties.etag = etag;

      source_conn = sync_env->svc->zone->get_zone_conn(sc->source_zone);
      if (!source_conn) {
        return set_cr_error(-EIO);
      }
      reader.reset(new rgw::sync::s3::StreamGetCRF(
        cct, get_env(), this, sync_env->http_manager, source_conn,
        source_obj, properties));
      writer.reset(new rgw::sync::s3::StreamPutCRF(
        cct, get_env(), this, sync_env->http_manager, context->target,
        destination_obj, rgw::tenant_cloud::copy_safe_headers,
        rgw::sync::s3::WriteErrorPolicy::retry_marker_ignored));

      yield call(new RGWStreamSpliceCR(
        cct, sync_env->http_manager, reader, writer));
      if (retcode < 0) {
        return set_cr_error(retcode);
      }
      return set_cr_done();
    }
    return 0;
  }
};

class RGWTenantCloudStatPutCR final : public RGWCallStatRemoteObjCR {
  rgw_bucket_sync_pipe sync_pipe;
  std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider;
  rgw::tenant_cloud::Config config;

public:
  RGWTenantCloudStatPutCR(
    RGWDataSyncCtx* sync, rgw_bucket_sync_pipe& sync_pipe, rgw_obj_key& key,
    std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider,
    rgw::tenant_cloud::Config config)
    : RGWCallStatRemoteObjCR(sync, sync_pipe.info.source_bs.bucket, key),
      sync_pipe(sync_pipe), provider(std::move(provider)),
      config(std::move(config)) {}

  RGWStatRemoteObjCBCR* allocate_callback() override
  {
    return new RGWTenantCloudPutCBCR(sc, sync_pipe, key, provider, config);
  }
};

class RGWTenantCloudPutCR final : public RGWCoroutine {
  RGWDataSyncCtx* sync;
  rgw_bucket_sync_pipe sync_pipe;
  rgw_obj_key key;
  std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider;
  std::optional<rgw::tenant_cloud::Config> config;
  int config_result;
  std::unique_ptr<RGWCoroutine> operation;

public:
  RGWTenantCloudPutCR(
    RGWDataSyncCtx* sync, rgw_bucket_sync_pipe& sync_pipe, rgw_obj_key& key,
    std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider)
    : RGWCoroutine(sync->cct), sync(sync), sync_pipe(sync_pipe), key(key),
      provider(std::move(provider)), config(),
      config_result(rgw::tenant_cloud::decode_config(
        sync_pipe.source_bucket_attrs, &config))
  {
    if (config_result == 0 && config) {
      std::string error;
      config_result = rgw::tenant_cloud::validate(*config, &error);
    }
  }

  int operate(const DoutPrefixProvider*) override
  {
    reenter(this) {
      if (config_result < 0 || !config || !config->enabled || !provider ||
          !pipe_matches_source(sync_pipe) ||
          sync->source_zone.id != config->source_zone_id ||
          key.need_to_encode_instance() ||
          !key.ns.empty()) {
        return set_cr_error(-EIO);
      }
      operation.reset(new RGWTenantCloudStatPutCR(
        sync, sync_pipe, key, provider, *config));
      yield call(operation.release());
      if (retcode < 0) {
        return set_cr_error(retcode);
      }
      return set_cr_done();
    }
    return 0;
  }
};

class RGWTenantCloudDataSyncModule : public RGWDataSyncModule {
  std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider;

public:
  explicit RGWTenantCloudDataSyncModule(
    std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider)
    : provider(std::move(provider)) {}

  RGWCoroutine* sync_object(
    const DoutPrefixProvider*, RGWDataSyncCtx* sync,
    rgw_bucket_sync_pipe& sync_pipe, rgw_obj_key& key,
    std::optional<uint64_t>, const rgw_zone_set_entry&,
    rgw_zone_set*) override
  {
    return new RGWTenantCloudPutCR(sync, sync_pipe, key, provider);
  }

  RGWCoroutine* remove_object(
    const DoutPrefixProvider*, RGWDataSyncCtx* sync,
    rgw_bucket_sync_pipe& sync_pipe, rgw_obj_key& key, real_time&,
    bool versioned, uint64_t, rgw_zone_set*) override
  {
    if (versioned) {
      return new RGWTenantCloudUnimplementedCR(
        sync->cct, "versioned DELETE");
    }
    return new RGWTenantCloudDeleteCR(sync, sync_pipe, key, provider);
  }

  RGWCoroutine* create_delete_marker(
    const DoutPrefixProvider* dpp, RGWDataSyncCtx*,
    rgw_bucket_sync_pipe&, rgw_obj_key&, real_time&,
    rgw_bucket_entry_owner&, bool, uint64_t, rgw_zone_set*) override
  {
    return new RGWTenantCloudUnimplementedCR(
      dpp->get_cct(), "DELETE marker");
  }
};

class RGWTenantCloudSyncModuleInstance : public RGWSyncModuleInstance {
  RGWTenantCloudDataSyncModule data_handler;

public:
  explicit RGWTenantCloudSyncModuleInstance(
    std::shared_ptr<rgw::tenant_cloud::TargetContextProvider> provider)
    : data_handler(std::move(provider)) {}

  RGWDataSyncModule* get_data_handler() override
  {
    return &data_handler;
  }
};

} // anonymous namespace

namespace rgw::tenant_cloud {

int target_bucket_name(const Config& config, std::string* bucket)
{
  if (!bucket) {
    return -EINVAL;
  }
  auto target = ARN::parse(config.target_bucket_arn);
  if (!target || target->service != rgw::Service::s3 ||
      !target->region.empty() || !target->account.empty() ||
      target->resource.empty() ||
      target->resource.find_first_of("/:") != std::string::npos) {
    return -EINVAL;
  }
  *bucket = target->resource;
  return 0;
}

int validate_target_context(const TargetContext& context,
                            const rgw_owner& owner,
                            const std::string& bucket_instance_id,
                            const Config& config)
{
  std::string destination_bucket;
  if (target_bucket_name(config, &destination_bucket) < 0 ||
      context.owner != owner ||
      context.bucket_instance_id != bucket_instance_id ||
      context.config_generation != config.config_generation ||
      context.destination_bucket != destination_bucket ||
      context.source_zone_id != config.source_zone_id ||
      context.endpoint != config.endpoint ||
      context.credential_ref != config.credential_ref ||
      context.target_zone_id != config.target_zone_id ||
      context.region != config.region ||
      context.host_style != config.host_style || !context.target) {
    return -EINVAL;
  }
  return 0;
}

int build_target_context(CephContext* cct,
                         const rgw_owner& owner,
                         const std::string& bucket_instance_id,
                         const std::string& source_zonegroup_id,
                         const Config& config,
                         const Credentials& credentials,
                         TargetContextRef* result)
{
  if (!cct || !result || validate(config, nullptr) < 0 ||
      credentials.version != 1 || credentials.access_key_id.empty() ||
      credentials.secret_key.empty() ||
      (credentials.session_token && credentials.session_token->empty())) {
    return -EINVAL;
  }

  std::string destination_bucket;
  if (target_bucket_name(config, &destination_bucket) < 0) {
    return -EINVAL;
  }

  auto conn = std::make_shared<S3RESTConn>(
    cct, "tenant-cloud", std::list<std::string>{config.endpoint},
    RGWOutboundCredentials(credentials.access_key_id,
                           credentials.secret_key,
                           credentials.session_token),
    source_zonegroup_id, config.region, PathStyle,
    RGWEndpointSelectionPolicy::require_pinned);
  auto target = rgw::sync::s3::make_rest_target(conn);
  if (!target) {
    return -EIO;
  }

  auto context = std::make_shared<TargetContext>();
  context->owner = owner;
  context->bucket_instance_id = bucket_instance_id;
  context->config_generation = config.config_generation;
  context->destination_bucket = std::move(destination_bucket);
  context->source_zone_id = config.source_zone_id;
  context->endpoint = config.endpoint;
  context->credential_ref = config.credential_ref;
  context->target_zone_id = config.target_zone_id;
  context->region = config.region;
  context->host_style = config.host_style;
  context->target = std::move(target);
  *result = std::move(context);
  return 0;
}

std::shared_ptr<TargetContextProvider> make_resolving_target_context_provider(
  std::shared_ptr<CredentialResolver> resolver)
{
  return resolver ? std::make_shared<RGWTenantCloudResolvedProvider>(
                      std::move(resolver)) : nullptr;
}

int make_delete_path(const TargetContext& context, const rgw_obj_key& key,
                     std::string* path)
{
  if (!path || context.destination_bucket.empty() ||
      key.need_to_encode_instance() ||
      !key.ns.empty()) {
    return -EINVAL;
  }
  // RGWRESTStreamRWRequest::send_prepare() performs the canonical URL encoding.
  // Passing pre-encoded data here would encode '%' a second time.
  *path = context.destination_bucket + "/" + key.name;
  return 0;
}

int make_put_objects(const TargetContext& context,
                     const rgw_bucket& source_bucket,
                     const rgw_obj_key& key, rgw_obj* source,
                     rgw_obj* destination)
{
  if (!source || !destination || context.destination_bucket.empty() ||
      key.need_to_encode_instance() ||
      !key.ns.empty()) {
    return -EINVAL;
  }
  source->bucket = source_bucket;
  source->key = key;
  destination->bucket = rgw_bucket{};
  destination->bucket.name = context.destination_bucket;
  destination->key.set(key.name);
  return 0;
}

int decode_source_properties(const std::map<std::string, bufferlist>& attrs,
                             rgw::sync::s3::SourceProperties* properties)
{
  if (!properties) {
    return -EINVAL;
  }
  const auto decode_attr = [&attrs]<typename T>(const char* name, T* value) {
    const auto i = attrs.find(name);
    if (i == attrs.end() || i->second.length() == 0) {
      *value = T{};
      return 0;
    }
    auto p = i->second.cbegin();
    try {
      ceph::decode(*value, p);
    } catch (const buffer::error&) {
      return -EIO;
    }
    return 0;
  };
  if (decode_attr(RGW_ATTR_SOURCE_ZONE, &properties->zone_short_id) < 0 ||
      decode_attr(RGW_ATTR_PG_VER, &properties->pg_ver) < 0) {
    return -EIO;
  }
  return 0;
}

void copy_safe_headers(const DoutPrefixProvider*, const rgw_rest_obj& source,
                       std::map<std::string, std::string>* destination)
{
  if (!destination) {
    return;
  }
  destination->clear();
  static constexpr std::string_view names[] = {
    "CONTENT_TYPE", "CONTENT_ENCODING",
    "CONTENT_DISPOSITION", "CONTENT_LANGUAGE"
  };
  for (const auto name : names) {
    const auto i = source.attrs.find(std::string{name});
    if (i != source.attrs.end()) {
      destination->emplace(i->first, i->second);
    }
  }
}

std::unique_ptr<RGWDataSyncModule> make_data_sync_module(
  std::shared_ptr<TargetContextProvider> provider)
{
  return std::make_unique<RGWTenantCloudDataSyncModule>(std::move(provider));
}

} // namespace rgw::tenant_cloud

int RGWTenantCloudSyncModule::create_instance(
  const DoutPrefixProvider*, CephContext* cct, const JSONFormattable&,
  RGWSyncModuleInstanceRef* instance)
{
  if (!cct || !instance) {
    return -EINVAL;
  }
  RGWVaultConfig vault_config{
    .address = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_addr"),
    .auth = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_auth"),
    .token_file = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_token_file"),
    .namespace_name = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_namespace"),
    .prefix = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_prefix"),
    .ssl_cacert = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_ssl_cacert"),
    .ssl_clientcert = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_ssl_clientcert"),
    .ssl_clientkey = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_ssl_clientkey"),
    .verify_ssl = cct->_conf.get_val<bool>(
      "rgw_tenant_cloud_vault_verify_ssl"),
  };
  auto credentials = std::make_shared<rgw::tenant_cloud::VaultCredentialResolver>(
    cct, std::move(vault_config),
    std::make_shared<rgw::tenant_cloud::CredentialCache>(
      cct->_conf.get_val<uint64_t>(
        "rgw_tenant_cloud_credential_cache_size"),
      std::chrono::seconds{cct->_conf.get_val<uint64_t>(
        "rgw_tenant_cloud_credential_cache_ttl_secs")}));
  auto provider = rgw::tenant_cloud::make_resolving_target_context_provider(
    std::move(credentials));
  instance->reset(new RGWTenantCloudSyncModuleInstance(std::move(provider)));
  return 0;
}

#include <boost/asio/unyield.hpp>
