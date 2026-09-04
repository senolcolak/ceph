// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include <cerrno>
#include <chrono>
#include <list>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "global/global_context.h"
#include "rgw_bucket_sync.h"
#include "rgw_data_sync.h"
#include "rgw_sync_module_tenant_cloud.h"

#include <boost/asio/yield.hpp>

namespace tc = rgw::tenant_cloud;
namespace s3 = rgw::sync::s3;

namespace {

class DoneCR final : public RGWCoroutine {
  int result;
public:
  explicit DoneCR(CephContext* cct, int result = 0)
    : RGWCoroutine(cct), result(result) {}
  int operate(const DoutPrefixProvider*) override {
    return result < 0 ? set_cr_error(result) : set_cr_done();
  }
};

class DelayedErrorCR final : public RGWCoroutine {
  int result;

public:
  DelayedErrorCR(CephContext* cct, int result)
    : RGWCoroutine(cct), result(result) {}

  int operate(const DoutPrefixProvider*) override
  {
    reenter(this) {
      yield wait(utime_t{0, 1000});
      return set_cr_error(result);
    }
    return 0;
  }
};

class ResolveCR final : public RGWCoroutine {
  tc::TargetContextRef context;
  tc::TargetContextRef* result;
  int resolve_result;

public:
  ResolveCR(CephContext* cct, tc::TargetContextRef context,
            tc::TargetContextRef* result, int resolve_result)
    : RGWCoroutine(cct), context(std::move(context)), result(result),
      resolve_result(resolve_result) {}

  int operate(const DoutPrefixProvider*) override
  {
    if (resolve_result < 0) {
      return set_cr_error(resolve_result);
    }
    *result = std::move(context);
    result = nullptr;
    return set_cr_done();
  }
};

class FakeTarget final : public s3::Target {
public:
  bool delete_called{false};
  unsigned delete_count{0};
  int delete_result{0};
  int delete_status{0};
  int init_put(const rgw_obj&, RGWRESTStreamS3PutObj**) override
  {
    return -EIO;
  }
  void send_ready(const DoutPrefixProvider*, RGWRESTStreamS3PutObj*,
                  const rgw_rest_obj&,
                  const std::map<std::string, std::string>&) override {}
  RGWCoroutine* delete_object(CephContext* cct, RGWHTTPManager*,
                              std::string, bool*, int* http_status) override
  {
    delete_called = true;
    ++delete_count;
    if (http_status) {
      *http_status = delete_status;
    }
    return new DoneCR(cct, delete_result);
  }
};

class FakeProvider final : public tc::TargetContextProvider {
public:
  tc::TargetContextRef context;
  std::shared_ptr<FakeTarget> target;
  int resolve_result{0};
  unsigned resolve_count{0};
  unsigned invalidate_count{0};
  bool recover_on_invalidate{false};

  FakeProvider()
  {
    auto value = std::make_shared<tc::TargetContext>();
    value->owner = rgw_user{"tenant$user"};
    value->bucket_instance_id = "bucket-instance";
    value->config_generation = 7;
    value->destination_bucket = "archive-bucket";
    value->source_zone_id = "source-zone";
    value->endpoint = "https://s3.example.test";
    value->credential_ref = "vault://archive";
    value->target_zone_id = "tenant-cloud-zone";
    value->region = "eu-central-1";
    value->host_style = "path";
    target = std::make_shared<FakeTarget>();
    value->target = target;
    context = std::move(value);
  }

  RGWCoroutine* resolve(const DoutPrefixProvider*, RGWDataSyncCtx* sync,
                        rgw_owner,
                        std::string, tc::Config,
                        tc::TargetContextRef* result) override
  {
    ++resolve_count;
    return new ResolveCR(sync->cct, context, result, resolve_result);
  }

  void invalidate(rgw_owner, const std::string&, const tc::Config&) override
  {
    ++invalidate_count;
    if (recover_on_invalidate) {
      target->delete_result = 0;
      target->delete_status = 0;
    }
  }
};

class FakeCredentialResolver final : public tc::CredentialResolver {
public:
  unsigned resolve_count{0};
  unsigned invalidate_count{0};

  RGWCoroutine* resolve(rgw_owner, tc::Config, tc::Credentials*) override
  {
    ++resolve_count;
    return new DelayedErrorCR(g_ceph_context, -EIO);
  }

  void invalidate(rgw_owner, const tc::Config&) override
  {
    ++invalidate_count;
  }
};

tc::Config config()
{
  tc::Config result;
  result.rule_id = "external-backup";
  result.target_bucket_arn = "arn:aws:s3:::archive-bucket";
  result.source_zone_id = "source-zone";
  result.config_generation = 7;
  result.endpoint = "https://s3.example.test";
  result.credential_ref = "vault://archive";
  result.target_zone_id = "tenant-cloud-zone";
  result.region = "eu-central-1";
  result.host_style = "path";
  return result;
}

tc::TargetContext context()
{
  tc::TargetContext result;
  result.owner = rgw_user{"tenant$user"};
  result.bucket_instance_id = "bucket-instance";
  result.config_generation = 7;
  result.destination_bucket = "archive-bucket";
  result.source_zone_id = "source-zone";
  result.endpoint = "https://s3.example.test";
  result.credential_ref = "vault://archive";
  result.target_zone_id = "tenant-cloud-zone";
  result.region = "eu-central-1";
  result.host_style = "path";
  result.target = std::make_shared<FakeTarget>();
  return result;
}

rgw_bucket_sync_pipe sync_pipe()
{
  rgw_bucket_sync_pipe pipe;
  pipe.source_bucket_info.owner = rgw_user{"tenant$user"};
  pipe.source_bucket_info.bucket =
    rgw_bucket{"tenant", "source-bucket", "bucket-instance"};
  pipe.info.source_bs.bucket = pipe.source_bucket_info.bucket;
  pipe.info.dest_bucket = pipe.source_bucket_info.bucket;
  auto cfg = config();
  cfg.rule_id = "external-backup";
  cfg.enabled = true;
  tc::encode_config(cfg, &pipe.source_bucket_attrs);
  return pipe;
}

TEST(RGWTenantCloudSync, ValidatesResolvedIdentity)
{
  const auto expected = context();
  const auto expected_config = config();
  EXPECT_EQ(0, tc::validate_target_context(
                 expected, expected.owner, "bucket-instance",
                 expected_config));

  auto stale = expected;
  stale.config_generation = 6;
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       stale, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_bucket = expected;
  wrong_bucket.destination_bucket = "other";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_bucket, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_endpoint = expected;
  wrong_endpoint.endpoint = "https://other.example.test";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_endpoint, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_owner = expected;
  wrong_owner.owner = rgw_user{"tenant$other"};
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_owner, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_instance = expected;
  wrong_instance.bucket_instance_id = "other-instance";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_instance, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_credential = expected;
  wrong_credential.credential_ref = "vault://other";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_credential, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_source_zone = expected;
  wrong_source_zone.source_zone_id = "other-zone";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_source_zone, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_target_zone = expected;
  wrong_target_zone.target_zone_id = "other-zone";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_target_zone, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_region = expected;
  wrong_region.region = "us-east-1";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_region, expected.owner, "bucket-instance",
                       expected_config));

  auto wrong_style = expected;
  wrong_style.host_style = "virtual";
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       wrong_style, expected.owner, "bucket-instance",
                       expected_config));

  auto null_target = expected;
  null_target.target.reset();
  EXPECT_EQ(-EINVAL, tc::validate_target_context(
                       null_target, expected.owner, "bucket-instance",
                       expected_config));
}

TEST(RGWTenantCloudSync, ConstructsDataModuleWithInjectedProvider)
{
  auto provider = std::make_shared<FakeProvider>();
  auto module = tc::make_data_sync_module(provider);
  EXPECT_NE(nullptr, module);
}

TEST(RGWTenantCloudSync, InvalidatesContextAndCredentialResolverTogether)
{
  auto resolver = std::make_shared<FakeCredentialResolver>();
  auto provider = tc::make_resolving_target_context_provider(
    resolver, 4, std::chrono::seconds{300});
  ASSERT_TRUE(provider);
  provider->invalidate(rgw_user{"tenant$user"}, "bucket-instance", config());
  EXPECT_EQ(1u, resolver->invalidate_count);
}

TEST(RGWTenantCloudSync, CoalescesConcurrentResolutionFailure)
{
  const auto previous_allowlist = g_ceph_context->_conf.get_val<std::string>(
    "rgw_tenant_cloud_endpoint_allowlist");
  g_ceph_context->_conf.set_val_or_die(
    "rgw_tenant_cloud_endpoint_allowlist", "s3.example.test");
  g_ceph_context->_conf.apply_changes(nullptr);
  struct AllowlistRestore {
    std::string value;
    ~AllowlistRestore() {
      g_ceph_context->_conf.set_val_or_die(
        "rgw_tenant_cloud_endpoint_allowlist", value);
      g_ceph_context->_conf.apply_changes(nullptr);
    }
  } restore{previous_allowlist};

  auto credential_resolver = std::make_shared<FakeCredentialResolver>();
  auto provider = tc::make_resolving_target_context_provider(
    credential_resolver, 4, std::chrono::seconds{300});
  RGWDataSyncEnv env;
  env.cct = g_ceph_context;
  RGWDataSyncCtx sync;
  sync.env = &env;
  sync.cct = g_ceph_context;
  tc::TargetContextRef first_result;
  tc::TargetContextRef second_result;
  auto cfg = config();
  auto* first = provider->resolve(nullptr, &sync, rgw_user{"tenant$user"},
                                  "bucket-instance", cfg, &first_result);
  auto* second = provider->resolve(nullptr, &sync, rgw_user{"tenant$user"},
                                   "bucket-instance", cfg, &second_result);
  ASSERT_NE(nullptr, first);
  ASSERT_NE(nullptr, second);

  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  std::list<RGWCoroutinesStack*> stacks;
  first->get();
  auto* first_stack = manager.allocate_stack();
  first_stack->call(first);
  stacks.push_back(first_stack);
  second->get();
  auto* second_stack = manager.allocate_stack();
  second_stack->call(second);
  stacks.push_back(second_stack);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  manager.run(&dpp, stacks);

  EXPECT_EQ(-EIO, first->get_ret_status());
  EXPECT_EQ(-EIO, second->get_ret_status());
  EXPECT_EQ(1u, credential_resolver->resolve_count);
  EXPECT_FALSE(first_result);
  EXPECT_FALSE(second_result);
  first->put();
  second->put();
}

TEST(RGWTenantCloudSync, BuildsStrictTargetContextFromCredentials)
{
  auto cfg = config();
  tc::Credentials credentials;
  credentials.version = 1;
  credentials.access_key_id = "temporary-access";
  credentials.secret_key = "temporary-secret";
  credentials.session_token = "temporary-session";
  credentials.cache_expires_at = 2000000000;

  tc::TargetContextRef context;
  const auto previous_allowlist = g_ceph_context->_conf.get_val<std::string>(
    "rgw_tenant_cloud_endpoint_allowlist");
  g_ceph_context->_conf.set_val_or_die(
    "rgw_tenant_cloud_endpoint_allowlist", "");
  g_ceph_context->_conf.apply_changes(nullptr);
  EXPECT_EQ(-EINVAL, tc::build_target_context(
                g_ceph_context, rgw_user{"tenant$user"},
                "bucket-instance", "source-zonegroup", cfg, credentials,
                &context));
  g_ceph_context->_conf.set_val_or_die(
    "rgw_tenant_cloud_endpoint_allowlist", "s3.example.test");
  g_ceph_context->_conf.apply_changes(nullptr);
  const int result = tc::build_target_context(
    g_ceph_context, rgw_user{"tenant$user"}, "bucket-instance",
    "source-zonegroup", cfg, credentials, &context);
  g_ceph_context->_conf.set_val_or_die(
    "rgw_tenant_cloud_endpoint_allowlist", previous_allowlist);
  g_ceph_context->_conf.apply_changes(nullptr);
  ASSERT_EQ(0, result);
  ASSERT_TRUE(context);
  EXPECT_EQ(cfg.target_zone_id, context->target_zone_id);
  EXPECT_EQ(cfg.credential_ref, context->credential_ref);
  EXPECT_EQ(credentials.cache_expires_at,
            context->credentials_refresh_at);
  EXPECT_NE(nullptr, context->target);
}

TEST(RGWTenantCloudSync, CredentialCacheIsOwnerScopedAndBounded)
{
  tc::CredentialCache cache(1, std::chrono::seconds{300});
  tc::Credentials first;
  first.version = 1;
  first.access_key_id = "first";
  first.secret_key = "secret";
  const auto first_expiry = cache.put("owner-a:cred", first);
  ASSERT_TRUE(first_expiry);

  tc::Credentials actual;
  ASSERT_TRUE(cache.get("owner-a:cred", &actual));
  EXPECT_EQ("first", actual.access_key_id);
  EXPECT_EQ(first_expiry, actual.cache_expires_at);
  EXPECT_FALSE(cache.get("owner-b:cred", &actual));

  tc::Credentials second = first;
  second.access_key_id = "second";
  cache.put("owner-b:cred", second);
  EXPECT_FALSE(cache.get("owner-a:cred", &actual));
  ASSERT_TRUE(cache.get("owner-b:cred", &actual));
  EXPECT_EQ("second", actual.access_key_id);
}

TEST(RGWTenantCloudSync, CredentialCacheRefreshesBeforeProviderExpiry)
{
  tc::CredentialCache cache(4, std::chrono::seconds{300});
  tc::Credentials credentials;
  credentials.version = 1;
  credentials.access_key_id = "soon-expired";
  credentials.secret_key = "secret";
  credentials.expires_at = static_cast<uint64_t>(
    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) + 10);
  cache.put("owner:cred", credentials);
  EXPECT_FALSE(cache.get("owner:cred", &credentials));
}

TEST(RGWTenantCloudSync, CredentialCacheInvalidatesRotatedCredentials)
{
  tc::CredentialCache cache(4, std::chrono::seconds{300});
  tc::Credentials credentials;
  credentials.version = 1;
  credentials.access_key_id = "stale";
  credentials.secret_key = "secret";
  const auto generation = cache.get_generation("owner:cred");
  cache.put("owner:cred", credentials);
  cache.invalidate("owner:cred");
  EXPECT_FALSE(cache.generation_is_current("owner:cred", generation));
  EXPECT_FALSE(cache.get("owner:cred", &credentials));
  EXPECT_FALSE(cache.put("owner:cred", credentials, &generation));
  EXPECT_FALSE(cache.get("owner:cred", &credentials));
}

TEST(RGWTenantCloudSync, CredentialCacheInvalidationIsKeyScoped)
{
  tc::CredentialCache cache(4, std::chrono::seconds{300});
  tc::Credentials credentials;
  credentials.version = 1;
  credentials.access_key_id = "access";
  credentials.secret_key = "secret";

  const auto first_generation = cache.get_generation("owner-a:cred");
  const auto second_generation = cache.get_generation("owner-b:cred");
  cache.invalidate("owner-a:cred");

  EXPECT_FALSE(cache.put("owner-a:cred", credentials, &first_generation));
  EXPECT_TRUE(cache.put("owner-b:cred", credentials, &second_generation));
}

TEST(RGWTenantCloudSync, RunsInjectedProviderDeleteCoroutine)
{
  auto provider = std::make_shared<FakeProvider>();
  auto module = tc::make_data_sync_module(provider);

  RGWDataSyncEnv env;
  env.cct = g_ceph_context;
  RGWDataSyncCtx sync;
  sync.env = &env;
  sync.cct = g_ceph_context;
  sync.source_zone = rgw_zone_id{"source-zone"};

  auto pipe = sync_pipe();

  rgw_obj_key key{"object"};
  real_time mtime;
  auto* operation = module->remove_object(nullptr, &sync, pipe, key, mtime,
                                          false, 0, nullptr);
  ASSERT_NE(nullptr, operation);
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(0, manager.run(&dpp, operation));
  EXPECT_EQ(1u, provider->resolve_count);
  EXPECT_TRUE(provider->target->delete_called);
}

TEST(RGWTenantCloudSync, RefreshesCredentialsOnceAfterDeleteAuthFailure)
{
  auto provider = std::make_shared<FakeProvider>();
  provider->target->delete_result = -EACCES;
  provider->target->delete_status = 403;
  provider->recover_on_invalidate = true;
  auto module = tc::make_data_sync_module(provider);

  RGWDataSyncEnv env;
  env.cct = g_ceph_context;
  RGWDataSyncCtx sync;
  sync.env = &env;
  sync.cct = g_ceph_context;
  sync.source_zone = rgw_zone_id{"source-zone"};
  auto pipe = sync_pipe();
  rgw_obj_key key{"object"};
  real_time mtime;
  auto* operation = module->remove_object(nullptr, &sync, pipe, key, mtime,
                                          false, 0, nullptr);
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(0, manager.run(&dpp, operation));
  EXPECT_EQ(2u, provider->resolve_count);
  EXPECT_EQ(1u, provider->invalidate_count);
  EXPECT_EQ(2u, provider->target->delete_count);
}

TEST(RGWTenantCloudSync, StopsAfterSecondDeleteAuthFailure)
{
  auto provider = std::make_shared<FakeProvider>();
  provider->target->delete_result = -EACCES;
  provider->target->delete_status = 401;
  auto module = tc::make_data_sync_module(provider);

  RGWDataSyncEnv env;
  env.cct = g_ceph_context;
  RGWDataSyncCtx sync;
  sync.env = &env;
  sync.cct = g_ceph_context;
  sync.source_zone = rgw_zone_id{"source-zone"};
  auto pipe = sync_pipe();
  rgw_obj_key key{"object"};
  real_time mtime;
  auto* operation = module->remove_object(nullptr, &sync, pipe, key, mtime,
                                          false, 0, nullptr);
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(-EIO, manager.run(&dpp, operation));
  EXPECT_EQ(2u, provider->resolve_count);
  EXPECT_EQ(1u, provider->invalidate_count);
  EXPECT_EQ(2u, provider->target->delete_count);
}

TEST(RGWTenantCloudSync, PreservesNonIgnoredProviderFailure)
{
  auto provider = std::make_shared<FakeProvider>();
  provider->resolve_result = -ECONNREFUSED;
  auto module = tc::make_data_sync_module(provider);
  RGWDataSyncEnv env;
  env.cct = g_ceph_context;
  RGWDataSyncCtx sync;
  sync.env = &env;
  sync.cct = g_ceph_context;
  sync.source_zone = rgw_zone_id{"source-zone"};
  auto pipe = sync_pipe();
  rgw_obj_key key{"object"};
  real_time mtime;
  auto* operation = module->remove_object(nullptr, &sync, pipe, key, mtime,
                                          false, 0, nullptr);
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(-ECONNREFUSED, manager.run(&dpp, operation));
  EXPECT_EQ(1u, provider->resolve_count);
  EXPECT_FALSE(provider->target->delete_called);
}

TEST(RGWTenantCloudSync, RejectsNonBucketArnInPathMapping)
{
  std::string bucket;
  auto invalid = config();
  invalid.target_bucket_arn = "arn:aws:s3:region:account:bucket/key";
  EXPECT_EQ(-EINVAL, tc::target_bucket_name(invalid, &bucket));
  EXPECT_EQ(-EINVAL, tc::target_bucket_name(config(), nullptr));
}

TEST(RGWTenantCloudSync, BuildsEncodedUnversionedDeletePath)
{
  const auto target = context();
  std::string path;
  EXPECT_EQ(0, tc::make_delete_path(
                 target, rgw_obj_key{"dir/a b%\xE2\x98\x83"}, &path));
  EXPECT_EQ("archive-bucket/dir/a b%\xE2\x98\x83", path);
  EXPECT_EQ(0, tc::make_delete_path(
                 target, rgw_obj_key{"key", "null"}, &path));
  EXPECT_EQ("archive-bucket/key", path);

  EXPECT_EQ(-EINVAL, tc::make_delete_path(
                       target, rgw_obj_key{"key", "version"}, &path));
  EXPECT_EQ(-EINVAL, tc::make_delete_path(
                       target, rgw_obj_key{"key", "", "namespace"},
                       &path));
}

TEST(RGWTenantCloudSync, MapsUnversionedPutObjects)
{
  const auto target = context();
  const rgw_bucket source_bucket{"tenant", "source", "instance"};
  rgw_obj source;
  rgw_obj destination;

  EXPECT_EQ(0, tc::make_put_objects(
                 target, source_bucket, rgw_obj_key{"dir/object"},
                 &source, &destination));
  EXPECT_EQ(source_bucket, source.bucket);
  EXPECT_EQ("dir/object", source.key.name);
  EXPECT_EQ("archive-bucket", destination.bucket.name);
  EXPECT_TRUE(destination.bucket.tenant.empty());
  EXPECT_TRUE(destination.bucket.bucket_id.empty());
  EXPECT_EQ("dir/object", destination.key.name);
  EXPECT_FALSE(destination.key.have_instance());
  EXPECT_TRUE(destination.key.ns.empty());

  EXPECT_EQ(0, tc::make_put_objects(
                 target, source_bucket, rgw_obj_key{"object", "null"},
                 &source, &destination));
  EXPECT_TRUE(source.key.have_null_instance());
  EXPECT_FALSE(destination.key.have_instance());
}

TEST(RGWTenantCloudSync, RejectsUnsupportedPutObjectKeys)
{
  const auto target = context();
  const rgw_bucket source_bucket{"tenant", "source", "instance"};
  rgw_obj source;
  rgw_obj destination;

  EXPECT_EQ(-EINVAL, tc::make_put_objects(
                       target, source_bucket,
                       rgw_obj_key{"object", "version"},
                       &source, &destination));
  EXPECT_EQ(-EINVAL, tc::make_put_objects(
                       target, source_bucket,
                       rgw_obj_key{"object", "", "namespace"},
                       &source, &destination));
  auto empty_target = target;
  empty_target.destination_bucket.clear();
  EXPECT_EQ(-EINVAL, tc::make_put_objects(
                       empty_target, source_bucket, rgw_obj_key{"object"},
                       &source, &destination));
  EXPECT_EQ(-EINVAL, tc::make_put_objects(
                       target, source_bucket, rgw_obj_key{"object"},
                       nullptr, &destination));
}

TEST(RGWTenantCloudSync, DecodesSourceConsistencyProperties)
{
  std::map<std::string, bufferlist> attrs;
  encode(uint32_t{12}, attrs[RGW_ATTR_SOURCE_ZONE]);
  encode(uint64_t{34}, attrs[RGW_ATTR_PG_VER]);
  s3::SourceProperties properties;
  EXPECT_EQ(0, tc::decode_source_properties(attrs, &properties));
  EXPECT_EQ(12u, properties.zone_short_id);
  EXPECT_EQ(34u, properties.pg_ver);

  attrs.clear();
  properties.zone_short_id = 1;
  properties.pg_ver = 1;
  EXPECT_EQ(0, tc::decode_source_properties(attrs, &properties));
  EXPECT_EQ(0u, properties.zone_short_id);
  EXPECT_EQ(0u, properties.pg_ver);

  attrs[RGW_ATTR_SOURCE_ZONE].append("x");
  EXPECT_EQ(-EIO, tc::decode_source_properties(attrs, &properties));
  attrs.clear();
  attrs[RGW_ATTR_PG_VER].clear();
  attrs[RGW_ATTR_PG_VER].append("x");
  EXPECT_EQ(-EIO, tc::decode_source_properties(attrs, &properties));
  EXPECT_EQ(-EINVAL, tc::decode_source_properties(attrs, nullptr));
}

TEST(RGWTenantCloudSync, CopiesOnlySafeContentHeaders)
{
  rgw_rest_obj source;
  source.attrs = {
    {"CONTENT_TYPE", "text/plain"},
    {"CONTENT_ENCODING", "gzip"},
    {"CONTENT_DISPOSITION", "attachment"},
    {"CONTENT_LANGUAGE", "en"},
    {"X_AMZ_META_SECRET", "do-not-copy"},
    {"UNRELATED", "do-not-copy"},
  };
  std::map<std::string, std::string> destination;
  destination.emplace("X_AMZ_META_STALE", "remove-me");
  tc::copy_safe_headers(nullptr, source, &destination);
  EXPECT_EQ(4u, destination.size());
  EXPECT_EQ("text/plain", destination["CONTENT_TYPE"]);
  EXPECT_EQ("gzip", destination["CONTENT_ENCODING"]);
  EXPECT_EQ("attachment", destination["CONTENT_DISPOSITION"]);
  EXPECT_EQ("en", destination["CONTENT_LANGUAGE"]);
  EXPECT_EQ(0u, destination.count("X_AMZ_META_SECRET"));
  EXPECT_EQ(0u, destination.count("X_AMZ_META_STALE"));
  EXPECT_EQ(0u, destination.count("UNRELATED"));
}

TEST(RGWTenantCloudSync, RejectsMixedDeletePipeBeforeResolution)
{
  auto provider = std::make_shared<FakeProvider>();
  auto module = tc::make_data_sync_module(provider);
  RGWDataSyncEnv env;
  env.cct = g_ceph_context;
  RGWDataSyncCtx sync;
  sync.env = &env;
  sync.cct = g_ceph_context;
  sync.source_zone = rgw_zone_id{"source-zone"};
  auto pipe = sync_pipe();
  pipe.info.source_bs.bucket.name = "other-source";
  rgw_obj_key key{"object"};
  real_time mtime;
  auto* operation = module->remove_object(nullptr, &sync, pipe, key, mtime,
                                          false, 0, nullptr);
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(-EIO, manager.run(&dpp, operation));
  EXPECT_EQ(0u, provider->resolve_count);
}

TEST(RGWTenantCloudSync, RejectsMixedPutPipeBeforeRemoteStat)
{
  auto provider = std::make_shared<FakeProvider>();
  auto module = tc::make_data_sync_module(provider);
  RGWDataSyncEnv env;
  env.cct = g_ceph_context;
  RGWDataSyncCtx sync;
  sync.env = &env;
  sync.cct = g_ceph_context;
  sync.source_zone = rgw_zone_id{"source-zone"};
  auto pipe = sync_pipe();
  pipe.info.source_bs.bucket.name = "other-source";
  rgw_obj_key key{"object"};
  rgw_zone_set_entry source_trace;
  auto* operation = module->sync_object(
    nullptr, &sync, pipe, key, std::nullopt, source_trace, nullptr);
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(-EIO, manager.run(&dpp, operation));
  EXPECT_EQ(0u, provider->resolve_count);
}

} // anonymous namespace

#include <boost/asio/unyield.hpp>
