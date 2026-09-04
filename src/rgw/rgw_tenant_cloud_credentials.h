#pragma once

#include "rgw_tenant_cloud.h"
#include "rgw_vault_client.h"
#include "rgw_user_types.h"

#include <chrono>
#include <list>
#include <mutex>
#include <unordered_map>

namespace rgw::tenant_cloud {

// Parse the versioned credential object from a Vault KV-v2 response.
int parse_vault_credentials(bufferlist& response, Credentials* result);

class CredentialResolver {
public:
  virtual ~CredentialResolver() = default;
  virtual RGWCoroutine* resolve(rgw_owner owner, Config config,
                                Credentials* result) = 0;
  virtual void invalidate(rgw_owner, const Config&) {}
};

class CredentialCache {
  struct Entry {
    Credentials credentials;
    std::chrono::system_clock::time_point expires;
    std::list<std::string>::iterator lru;
  };
  size_t max_entries;
  std::chrono::seconds ttl;
  std::mutex lock;
  std::unordered_map<std::string, std::weak_ptr<uint64_t>> generations;
  std::list<std::string> lru;
  std::unordered_map<std::string, Entry> entries;

public:
  struct Generation {
  private:
    std::shared_ptr<uint64_t> state;
    uint64_t value{0};
    friend class CredentialCache;
  };

  CredentialCache(size_t max_entries = 1024,
                  std::chrono::seconds ttl = std::chrono::seconds{300});
  ~CredentialCache();
  bool get(const std::string& key, Credentials* result);
  Generation get_generation(const std::string& key);
  bool generation_is_current(const std::string& key,
                             const Generation& generation);
  std::optional<uint64_t> put(const std::string& key,
                              Credentials credentials,
                              const Generation* expected_generation = nullptr);
  void invalidate(const std::string& key);
};

class VaultCredentialResolver final : public CredentialResolver {
  CephContext* cct;
  RGWVaultConfig vault_config;
  std::shared_ptr<CredentialCache> cache;

public:
  VaultCredentialResolver(CephContext* cct, RGWVaultConfig config,
                          std::shared_ptr<CredentialCache> cache = nullptr)
    : cct(cct), vault_config(std::move(config)),
      cache(cache ? std::move(cache) : std::make_shared<CredentialCache>()) {}

  RGWCoroutine* resolve(rgw_owner owner, Config config,
                        Credentials* result) override;
  void invalidate(rgw_owner owner, const Config& config) override;
};

} // namespace rgw::tenant_cloud
