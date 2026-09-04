// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_sync_module_tenant_cloud.h"
#include "rgw_tenant_cloud_credentials.h"

#include <cerrno>
#include <chrono>
#include <iterator>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "rgw_bucket_sync.h"
#include "rgw_data_sync.h"
#include "rgw_arn.h"
#include "rgw_tenant_cloud.h"
#include "services/svc_zone.h"

#include <boost/asio/yield.hpp>

#define dout_subsys ceph_subsys_rgw

namespace {

std::string context_cache_key(const rgw_owner& owner,
                              const std::string& bucket_instance_id,
                              uint64_t config_generation)
{
  const auto owner_string = to_string(owner);
  return std::to_string(owner_string.size()) + ":" + owner_string +
         std::to_string(bucket_instance_id.size()) + ":" +
         bucket_instance_id + std::to_string(config_generation);
}

bool pipe_matches_source(const rgw_bucket_sync_pipe& pipe)
{
  return pipe.info.source_bs.bucket == pipe.source_bucket_info.bucket &&
         pipe.info.dest_bucket == pipe.source_bucket_info.bucket;
}

class RGWTenantCloudResolvedProvider final
  : public rgw::tenant_cloud::TargetContextProvider,
    public std::enable_shared_from_this<RGWTenantCloudResolvedProvider> {
  std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver;
  mutable std::mutex cache_lock;
  struct CacheEntry {
    rgw::tenant_cloud::TargetContextRef context;
    std::chrono::steady_clock::time_point expires;
    std::list<std::string>::iterator lru;
  };
  size_t max_cache_entries;
  std::chrono::seconds cache_ttl;
  mutable std::list<std::string> cache_lru;
  mutable std::unordered_map<std::string, CacheEntry> cache;
  struct Inflight {
    bool done{false};
    int result{-EIO};
    rgw::tenant_cloud::TargetContextRef context;
  };
  std::unordered_map<std::string, std::shared_ptr<Inflight>> inflight;

  rgw::tenant_cloud::TargetContextRef get_cached(
    const std::string& key) const
  {
    std::lock_guard guard(cache_lock);
    auto iter = cache.find(key);
    if (iter == cache.end()) {
      return {};
    }
    if (std::chrono::steady_clock::now() >= iter->second.expires) {
      cache_lru.erase(iter->second.lru);
      cache.erase(iter);
      return {};
    }
    const auto& context = iter->second.context;
    const auto credentials_expiry = context->credentials_refresh_at;
    if (credentials_expiry) {
      const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
      if (now < 0 || *credentials_expiry <=
          static_cast<uint64_t>(now) + 30) {
        cache_lru.erase(iter->second.lru);
        cache.erase(iter);
        return {};
      }
    }
    cache_lru.splice(cache_lru.end(), cache_lru, iter->second.lru);
    return context;
  }

  void put_cached_locked(std::string key,
                         rgw::tenant_cloud::TargetContextRef context)
  {
    auto iter = cache.find(key);
    if (iter != cache.end()) {
      cache_lru.erase(iter->second.lru);
      cache.erase(iter);
    }
    if (max_cache_entries == 0 || cache_ttl <= std::chrono::seconds::zero()) {
      return;
    }
    cache_lru.push_back(key);
    cache.emplace(
      std::move(key),
      CacheEntry{std::move(context), std::chrono::steady_clock::now() + cache_ttl,
                 std::prev(cache_lru.end())});
    while (cache.size() > max_cache_entries) {
      auto old = cache.find(cache_lru.front());
      cache_lru.pop_front();
      if (old != cache.end()) {
        cache.erase(old);
      }
    }
  }

  void invalidate_cached(const std::string& key)
  {
    std::lock_guard guard(cache_lock);
    auto iter = cache.find(key);
    if (iter != cache.end()) {
      cache_lru.erase(iter->second.lru);
      cache.erase(iter);
    }
    auto pending = inflight.find(key);
    if (pending != inflight.end()) {
      pending->second->result = -ECANCELED;
      pending->second->context.reset();
      pending->second->done = true;
      inflight.erase(pending);
    }
  }

  std::shared_ptr<Inflight> join_resolution(const std::string& key,
                                            bool* leader)
  {
    std::lock_guard guard(cache_lock);
    auto iter = inflight.find(key);
    if (iter != inflight.end()) {
      *leader = false;
      return iter->second;
    }
    auto state = std::make_shared<Inflight>();
    inflight.emplace(key, state);
    *leader = true;
    return state;
  }

  bool finish_resolution(const std::string& key,
                         const std::shared_ptr<Inflight>& state,
                         int result,
                         rgw::tenant_cloud::TargetContextRef context)
  {
    std::lock_guard guard(cache_lock);
    if (state->done) {
      return false;
    }
    auto iter = inflight.find(key);
    if (iter == inflight.end() || iter->second != state) {
      return false;
    }
    state->result = result;
    state->context = context;
    state->done = true;
    if (result == 0) {
      put_cached_locked(key, std::move(context));
    }
    inflight.erase(iter);
    return true;
  }

  bool consume_resolution(const std::shared_ptr<Inflight>& state,
                          rgw::tenant_cloud::TargetContextRef* result,
                          int* ret)
  {
    std::lock_guard guard(cache_lock);
    if (!state->done) {
      return false;
    }
    *ret = state->result;
    if (state->result == 0 && result) {
      *result = state->context;
    }
    return true;
  }

  class ResolveCR final : public RGWCoroutine {
    RGWDataSyncCtx* sync;
    std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver;
    rgw_owner owner;
    std::string bucket_instance_id;
    rgw::tenant_cloud::Config config;
    rgw::tenant_cloud::TargetContextRef* result;
    std::shared_ptr<RGWTenantCloudResolvedProvider> parent;
    std::string cache_key;
    std::shared_ptr<RGWTenantCloudResolvedProvider::Inflight> inflight;
    bool leader{false};
    rgw::tenant_cloud::Credentials credentials;
    std::unique_ptr<RGWCoroutine> operation;

  public:
    ResolveCR(RGWDataSyncCtx* sync,
              std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver,
              rgw_owner owner, std::string bucket_instance_id,
              rgw::tenant_cloud::Config config,
              rgw::tenant_cloud::TargetContextRef* result,
              std::shared_ptr<RGWTenantCloudResolvedProvider> parent)
      : RGWCoroutine(sync->cct), sync(sync), resolver(std::move(resolver)),
        owner(std::move(owner)),
        bucket_instance_id(std::move(bucket_instance_id)),
        config(std::move(config)), result(result), parent(parent) {}

    ~ResolveCR() override
    {
      // A coroutine can be destroyed while waiting on Vault. Leaders
      // must publish a terminal result so that waiters never remain attached
      // to an abandoned in-flight resolution.
      if (leader && inflight) {
        parent->finish_resolution(cache_key, inflight, -ECANCELED, {});
      }
    }

    int operate(const DoutPrefixProvider*) override
    {
      reenter(this) {
        if (!resolver || !result) {
          return set_cr_error(-EINVAL);
        }
        // The operator allowlist is runtime-configurable. Recheck it even on
        // a cache hit so a removed destination cannot keep using a stale
        // target context until its TTL expires.
        if (rgw::tenant_cloud::validate_endpoint_policy(
              sync->cct, config, nullptr) < 0) {
          return set_cr_error(-EINVAL);
        }
        cache_key = context_cache_key(owner, bucket_instance_id,
                                      config.config_generation);
        if (auto cached = parent->get_cached(cache_key)) {
          *result = std::move(cached);
          return set_cr_done();
        }
        inflight = parent->join_resolution(cache_key, &leader);
        if (!leader) {
          while (!parent->consume_resolution(inflight, result, &retcode)) {
            yield wait(utime_t{0, 10000});
          }
          return retcode < 0 ? set_cr_error(retcode) : set_cr_done();
        }
        operation.reset(resolver->resolve(owner, config, &credentials));
        if (!operation) {
          parent->finish_resolution(cache_key, inflight, -EINVAL, {});
          return set_cr_error(-EINVAL);
        }
        yield call(operation.release());
        if (retcode < 0) {
          parent->finish_resolution(cache_key, inflight, retcode, {});
          return set_cr_error(retcode);
        }
        if (!sync->env || !sync->env->svc || !sync->env->svc->zone) {
          parent->finish_resolution(cache_key, inflight, -EINVAL, {});
          return set_cr_error(-EINVAL);
        }
        const int ret = rgw::tenant_cloud::build_target_context(
          sync->cct, owner, bucket_instance_id,
          sync->env->svc->zone->get_zonegroup().get_id(), config, credentials,
          result);
        if (ret < 0) {
          parent->finish_resolution(cache_key, inflight, ret, {});
          return set_cr_error(ret);
        }
        if (!parent->finish_resolution(cache_key, inflight, 0, *result)) {
          result->reset();
          return set_cr_error(-ECANCELED);
        }
        return set_cr_done();
      }
      return 0;
    }
  };

public:
  explicit RGWTenantCloudResolvedProvider(
    std::shared_ptr<rgw::tenant_cloud::CredentialResolver> resolver,
    size_t max_cache_entries, std::chrono::seconds cache_ttl)
    : resolver(std::move(resolver)), max_cache_entries(max_cache_entries),
      cache_ttl(cache_ttl) {}

  RGWCoroutine* resolve(const DoutPrefixProvider* dpp, RGWDataSyncCtx* sync,
                        rgw_owner owner, std::string bucket_instance_id,
                        rgw::tenant_cloud::Config config,
                        rgw::tenant_cloud::TargetContextRef* result) override
  {
    if (!sync || !sync->cct) {
      return nullptr;
    }
    return new ResolveCR(sync, resolver, std::move(owner),
                         std::move(bucket_instance_id), std::move(config), result,
                         shared_from_this());
  }

  void invalidate(rgw_owner owner, const std::string& bucket_instance_id,
                  const rgw::tenant_cloud::Config& config) override
  {
    resolver->invalidate(owner, config);
    invalidate_cached(context_cache_key(owner, bucket_instance_id,
                                        config.config_generation));
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
      << "ERROR: tenant-cloud replication does not support "
      << operation << dendl;

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
  rgw_bucket source_bucket;
  rgw_obj_key key;
  std::optional<rgw::tenant_cloud::Config> config;
  int config_result;
  bool pipe_matches;
  rgw::tenant_cloud::TargetContextRef context;
  std::unique_ptr<RGWCoroutine> resolver;
  std::string path;
  bool auth_retry{false};
  int http_status{0};
  ceph::real_time source_mtime;
  uint64_t source_size{0};
  std::string source_etag;
  std::map<std::string, bufferlist> source_attrs;
  std::map<std::string, std::string> source_headers;

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
      source_bucket(sync_pipe.source_bucket_info.bucket),
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

      // A delete event can be retried after a newer PUT has already appeared.
      // Recheck source state before deleting the destination; the normal data
      // sync ordering handles the remaining event when the object exists.
      // Unit tests with no RADOS service use the injected target directly.
      if (sync->env->async_rados) {
        yield call(new RGWStatRemoteObjCR(
          sync->env->async_rados, sync->env->driver, sync->source_zone,
          source_bucket, key, &source_mtime, &source_size, &source_etag,
          &source_attrs, &source_headers));
        if (retcode == 0) {
          return set_cr_done();
        }
        if (retcode != -ENOENT) {
          return set_cr_error(
            rgw::sync::s3::normalize_write_result(retcode));
        }
        retcode = 0;
      }

      while (true) {
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
        cct, context->target, sync->env->http_manager, path, &http_status));
      retcode = rgw::sync::s3::normalize_write_result(retcode);
      if (retcode < 0) {
        ldpp_dout(dpp, 0)
          << "tenant-cloud destination DELETE failed (endpoint="
          << config->endpoint << ", http_status=" << http_status
          << ", ret=" << retcode << ")" << dendl;
        if (!auth_retry && (http_status == 401 || http_status == 403)) {
          auth_retry = true;
          provider->invalidate(owner, bucket_instance_id, *config);
          retcode = 0;
          continue;
        }
        return set_cr_error(retcode);
      }
      return set_cr_done();
      }
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
  bool auth_retry{false};

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

      while (true) {
      context.reset();
      reader.reset();
      writer.reset();
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
        const int http_status = writer->get_http_status();
        ldpp_dout(dpp, 0)
          << "tenant-cloud destination PUT failed (endpoint="
          << config.endpoint << ", http_status=" << http_status
          << ", ret=" << retcode << ")" << dendl;
        if (!auth_retry && (http_status == 401 || http_status == 403)) {
          auth_retry = true;
          provider->invalidate(owner, bucket_instance_id, config);
          retcode = 0;
          continue;
        }
        return set_cr_error(retcode);
      }
      return set_cr_done();
      }
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
  if (validate_endpoint_policy(cct, config, nullptr) < 0) {
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
    RGWEndpointSelectionPolicy::require_pinned,
    RGWEndpointAddressPolicy::reject_prohibited);
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
  context->credentials_refresh_at = credentials.cache_expires_at
    ? credentials.cache_expires_at : credentials.expires_at;
  context->target = std::move(target);
  *result = std::move(context);
  return 0;
}

std::shared_ptr<TargetContextProvider> make_resolving_target_context_provider(
  std::shared_ptr<CredentialResolver> resolver, size_t max_cache_entries,
  std::chrono::seconds cache_ttl)
{
  return resolver ? std::make_shared<RGWTenantCloudResolvedProvider>(
                      std::move(resolver), max_cache_entries, cache_ttl) : nullptr;
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
  const auto configured_or_kms = [cct](const char* tenant_option,
                                       const char* kms_option) {
    auto value = cct->_conf.get_val<std::string>(tenant_option);
    if (value.empty()) {
      value = cct->_conf.get_val<std::string>(kms_option);
    }
    return value;
  };
  RGWVaultConfig vault_config{
    .address = configured_or_kms("rgw_tenant_cloud_vault_addr",
                                 "rgw_crypt_vault_addr"),
    .auth = configured_or_kms("rgw_tenant_cloud_vault_auth",
                              "rgw_crypt_vault_auth"),
    .token_file = configured_or_kms("rgw_tenant_cloud_vault_token_file",
                                    "rgw_crypt_vault_token_file"),
    .namespace_name = configured_or_kms("rgw_tenant_cloud_vault_namespace",
                                        "rgw_crypt_vault_namespace"),
    .prefix = cct->_conf.get_val<std::string>(
      "rgw_tenant_cloud_vault_prefix"),
    .ssl_cacert = configured_or_kms("rgw_tenant_cloud_vault_ssl_cacert",
                                    "rgw_crypt_vault_ssl_cacert"),
    .ssl_clientcert = configured_or_kms("rgw_tenant_cloud_vault_ssl_clientcert",
                                        "rgw_crypt_vault_ssl_clientcert"),
    .ssl_clientkey = configured_or_kms("rgw_tenant_cloud_vault_ssl_clientkey",
                                       "rgw_crypt_vault_ssl_clientkey"),
    .verify_ssl = cct->_conf.get_val<bool>(
      "rgw_tenant_cloud_vault_verify_ssl"),
  };
  const auto credential_cache_size = cct->_conf.get_val<uint64_t>(
    "rgw_tenant_cloud_credential_cache_size");
  const auto credential_cache_ttl = std::chrono::seconds{
    cct->_conf.get_val<uint64_t>(
      "rgw_tenant_cloud_credential_cache_ttl_secs")};
  auto credentials = std::make_shared<rgw::tenant_cloud::VaultCredentialResolver>(
    cct, std::move(vault_config),
    std::make_shared<rgw::tenant_cloud::CredentialCache>(
      credential_cache_size, credential_cache_ttl));
  auto provider = rgw::tenant_cloud::make_resolving_target_context_provider(
    std::move(credentials), credential_cache_size, credential_cache_ttl);
  instance->reset(new RGWTenantCloudSyncModuleInstance(std::move(provider)));
  return 0;
}

#include <boost/asio/unyield.hpp>
