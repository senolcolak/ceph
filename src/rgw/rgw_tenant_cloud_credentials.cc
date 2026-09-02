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

void CredentialCache::put(const std::string& key, Credentials credentials)
{
  if (max_entries == 0) {
    wipe(credentials);
    return;
  }
  const auto now = std::chrono::system_clock::now();
  auto expires = now + ttl;
  if (credentials.expires_at) {
    expires = std::min(expires,
      std::chrono::system_clock::time_point{std::chrono::seconds{*credentials.expires_at}});
  }
  if (expires <= now + std::chrono::seconds{30}) {
    wipe(credentials);
    return;
  }

  std::lock_guard guard(lock);
  auto i = entries.find(key);
  if (i != entries.end()) {
    wipe(i->second.credentials);
    i->second.credentials = std::move(credentials);
    i->second.expires = expires;
    lru.splice(lru.end(), lru, i->second.lru);
    return;
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
      cache_key = to_string(owner) + ":" + config.credential_ref;
      if (cache && cache->get(cache_key, result)) {
        return set_cr_done();
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
      if (cache) cache->put(cache_key, resolved);
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

} // namespace rgw::tenant_cloud

#include <boost/asio/unyield.hpp>
