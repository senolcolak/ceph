#include "rgw_tenant_cloud_credentials.h"

#include <cerrno>
#include <algorithm>
#include <memory>

#include "common/ceph_json.h"
#include "common/ceph_crypto.h"
#include "rgw_common.h"
#include "rgw_coroutine.h"

#include <boost/asio/yield.hpp>

namespace rgw::tenant_cloud {

namespace {
void wipe(Credentials& credentials)
{
  if (!credentials.access_key_id.empty()) {
    ::ceph::crypto::zeroize_for_security(credentials.access_key_id.data(),
                                         credentials.access_key_id.size());
  }
  if (!credentials.secret_key.empty()) {
    ::ceph::crypto::zeroize_for_security(credentials.secret_key.data(),
                                         credentials.secret_key.size());
  }
  if (credentials.session_token && !credentials.session_token->empty()) {
    ::ceph::crypto::zeroize_for_security(credentials.session_token->data(),
                                         credentials.session_token->size());
  }
}

void wipe(bufferlist& data)
{
  for (auto& buffer : data.mut_buffers()) {
    ::ceph::crypto::zeroize_for_security(buffer.c_str(), buffer.length());
  }
}

std::string credential_cache_key(const rgw_owner& owner,
                                 const std::string& credential_ref)
{
  const auto owner_string = to_string(owner);
  return std::to_string(owner_string.size()) + ":" + owner_string +
         credential_ref;
}
}

CredentialCache::CredentialCache(size_t max_entries, std::chrono::seconds ttl)
  : max_entries(max_entries), ttl(ttl) {}

CredentialCache::~CredentialCache()
{
  std::lock_guard guard(lock);
  for (auto& [key, entry] : entries) wipe(entry.credentials);
}

bool CredentialCache::get(const std::string& key, Credentials* result)
{
  if (!result) return false;
  std::lock_guard guard(lock);
  auto i = entries.find(key);
  if (i == entries.end()) return false;
  constexpr auto refresh_skew = std::chrono::seconds{30};
  if (std::chrono::system_clock::now() + refresh_skew >= i->second.expires) {
    wipe(i->second.credentials);
    lru.erase(i->second.lru);
    entries.erase(i);
    return false;
  }
  lru.splice(lru.end(), lru, i->second.lru);
  wipe(*result);
  *result = i->second.credentials;
  return true;
}

CredentialCache::Generation CredentialCache::get_generation(
  const std::string& key)
{
  std::lock_guard guard(lock);
  auto& weak = generations[key];
  auto state = weak.lock();
  if (!state) {
    state = std::make_shared<uint64_t>(0);
    weak = state;
  }
  Generation generation;
  generation.state = std::move(state);
  generation.value = *generation.state;
  return generation;
}

bool CredentialCache::generation_is_current(
  const std::string& key, const Generation& generation)
{
  std::lock_guard guard(lock);
  const auto iter = generations.find(key);
  const auto state = iter == generations.end() ? std::shared_ptr<uint64_t>{}
                                               : iter->second.lock();
  return state && generation.state && state == generation.state &&
         *state == generation.value;
}

std::optional<uint64_t> CredentialCache::put(
  const std::string& key, Credentials credentials,
  const Generation* expected_generation)
{
  if (max_entries == 0) {
    wipe(credentials);
    return std::nullopt;
  }
  const auto now = std::chrono::system_clock::now();
  auto expires = now + ttl;
  if (credentials.expires_at) {
    expires = std::min(expires,
      std::chrono::system_clock::time_point{std::chrono::seconds{*credentials.expires_at}});
  }
  if (expires <= now + std::chrono::seconds{30}) {
    wipe(credentials);
    return std::nullopt;
  }
  const auto expires_at = static_cast<uint64_t>(
    std::chrono::duration_cast<std::chrono::seconds>(
      expires.time_since_epoch()).count());
  credentials.cache_expires_at = expires_at;

  std::lock_guard guard(lock);
  if (expected_generation &&
      (!expected_generation->state ||
       *expected_generation->state != expected_generation->value)) {
    wipe(credentials);
    return std::nullopt;
  }
  auto i = entries.find(key);
  if (i != entries.end()) {
    wipe(i->second.credentials);
    i->second.credentials = std::move(credentials);
    i->second.expires = expires;
    lru.splice(lru.end(), lru, i->second.lru);
    return expires_at;
  }
  lru.push_back(key);
  entries.emplace(key, Entry{std::move(credentials), expires, std::prev(lru.end())});
  while (entries.size() > max_entries) {
    auto old = entries.find(lru.front());
    lru.pop_front();
    if (old != entries.end()) {
      wipe(old->second.credentials);
      entries.erase(old);
    }
  }
  return expires_at;
}

void CredentialCache::invalidate(const std::string& key)
{
  std::lock_guard guard(lock);
  auto& weak = generations[key];
  auto state = weak.lock();
  if (!state) {
    state = std::make_shared<uint64_t>(0);
    weak = state;
  }
  ++*state;
  auto i = entries.find(key);
  if (i == entries.end()) {
    return;
  }
  wipe(i->second.credentials);
  lru.erase(i->second.lru);
  entries.erase(i);
}

int parse_vault_credentials(bufferlist& response, Credentials* result)
{
  if (!result || response.length() == 0) return -EINVAL;
  JSONParser parser;
  if (!parser.parse(response.c_str(), response.length())) return -EINVAL;
  JSONObj* outer = parser.find_obj("data");
  JSONObj* data = outer ? outer->find_obj("data") : nullptr;
  if (!data) return -EINVAL;

  Credentials parsed;
  try {
    if (!JSONDecoder::decode_json("version", parsed.version, data, true) ||
        !JSONDecoder::decode_json("access_key_id", parsed.access_key_id, data, true) ||
        !JSONDecoder::decode_json("secret_key", parsed.secret_key, data, true)) {
      return -EINVAL;
    }
    JSONDecoder::decode_json("session_token", parsed.session_token, data);
    JSONDecoder::decode_json("expires_at", parsed.expires_at, data);
  } catch (const JSONDecoder::err&) {
    return -EINVAL;
  }
  if (parsed.version != 1 || parsed.access_key_id.empty() ||
      parsed.secret_key.empty() ||
      (parsed.session_token && parsed.session_token->empty())) {
    return -EINVAL;
  }
  wipe(*result);
  *result = std::move(parsed);
  return 0;
}

namespace {

class ResolveCR final : public RGWCoroutine {
  RGWVaultClient client;
  rgw_owner owner;
  Config config;
  Credentials* result;
  std::shared_ptr<CredentialCache> cache;
  std::string cache_key;
  CredentialCache::Generation cache_generation;
  bufferlist response;
  Credentials resolved;
  std::unique_ptr<RGWCoroutine> operation;

public:
  ResolveCR(CephContext* cct, RGWVaultConfig vault_config,
            rgw_owner owner, Config config, Credentials* result,
            std::shared_ptr<CredentialCache> cache)
    : RGWCoroutine(cct), client(cct, std::move(vault_config)),
      owner(std::move(owner)), config(std::move(config)), result(result),
      cache(std::move(cache)) {}

  ~ResolveCR() override
  {
    wipe(response);
    wipe(resolved);
  }

  int operate(const DoutPrefixProvider*) override
  {
    reenter(this) {
      if (!result || validate(config, nullptr) < 0) {
        return set_cr_error(-EINVAL);
      }
      cache_key = credential_cache_key(owner, config.credential_ref);
      if (cache && cache->get(cache_key, result)) {
        return set_cr_done();
      }
      if (cache) {
        cache_generation = cache->get_generation(cache_key);
      }
      {
        const std::string logical = config.credential_ref.substr(8);
        const std::string path = url_encode(to_string(owner), true) + "/" +
                                 url_encode(logical, true);
        operation.reset(client.request_async("GET", path, {}, &response));
      }
      if (!operation) return set_cr_error(-EINVAL);
      yield call(operation.release());
      if (retcode < 0) return set_cr_error(retcode);
      const int ret = parse_vault_credentials(response, &resolved);
      if (ret < 0) return set_cr_error(ret);
      if (resolved.expires_at) {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
        constexpr uint64_t refresh_skew = 30;
        if (now < 0 ||
            *resolved.expires_at <= static_cast<uint64_t>(now) + refresh_skew) {
          return set_cr_error(-EINVAL);
        }
      }
      if (cache) {
        const auto cache_expiry = cache->put(
          cache_key, resolved, &cache_generation);
        if (!cache_expiry) {
          // A missing expiry is normally valid when caching is disabled or
          // the provider credential is too close to expiry. It is not valid
          // when invalidation advanced this request's generation: publishing
          // that result would let stale in-flight credentials escape the
          // refresh fence.
          if (!cache->generation_is_current(cache_key, cache_generation)) {
            return set_cr_error(-ECANCELED);
          }
        }
        resolved.cache_expires_at = cache_expiry;
      }
      wipe(*result);
      *result = std::move(resolved);
      return set_cr_done();
    }
    return 0;
  }
};

} // anonymous namespace

RGWCoroutine* VaultCredentialResolver::resolve(
  rgw_owner owner, Config config, Credentials* result)
{
  if (!cct) return nullptr;
  return new ResolveCR(cct, vault_config, std::move(owner),
                       std::move(config), result, cache);
}

void VaultCredentialResolver::invalidate(rgw_owner owner,
                                         const Config& config)
{
  if (cache) {
    cache->invalidate(credential_cache_key(owner, config.credential_ref));
  }
}

} // namespace rgw::tenant_cloud

#include <boost/asio/unyield.hpp>
