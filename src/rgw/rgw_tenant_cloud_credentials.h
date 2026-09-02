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
  std::list<std::string> lru;
  std::unordered_map<std::string, Entry> entries;

public:
  CredentialCache(size_t max_entries = 1024,
                  std::chrono::seconds ttl = std::chrono::seconds{300});
  ~CredentialCache();
  bool get(const std::string& key, Credentials* result);
  void put(const std::string& key, Credentials credentials);
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
};

} // namespace rgw::tenant_cloud
