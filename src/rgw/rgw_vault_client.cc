// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
#include "rgw_vault_client.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>

#include "common/ceph_crypto.h"
#include "common/safe_io.h"
#include "rgw_secure_endpoint_resolver.h"
#ifdef WITH_RADOSGW_RADOS
#include "rgw_coroutine.h"
#endif

#ifdef WITH_RADOSGW_RADOS
#include <boost/asio/yield.hpp>
#endif

namespace {

class BoundedVaultResponse final : public RGWHTTPTransceiver {
  bufferlist* response;
  const size_t max_size;

public:
  BoundedVaultResponse(CephContext* cct, const std::string& method,
                       const RGWEndpoint& endpoint, bufferlist* response,
                       size_t max_size)
    : RGWHTTPTransceiver(cct, method, endpoint, response),
      response(response), max_size(max_size) {}

  int receive_data(void* ptr, size_t len, bool* pause) override
  {
    if (response->length() > max_size || len > max_size - response->length()) {
      return -EFBIG;
    }
    response->append(static_cast<const char*>(ptr), len);
    return 0;
  }
};

int load_token(const std::string& path, std::string* token);

bool is_vault_auth_failure(long status)
{
  return status == 401 || status == 403;
}

void append_url(std::string& url, std::string_view path)
{
  const bool slash = !url.empty() && url.back() == '/';
  if (path.empty()) {
    return;
  }
  if (slash && path.front() == '/') {
    url.pop_back();
  } else if (!slash && path.front() != '/') {
    url.push_back('/');
  }
  url.append(path);
}

#ifdef WITH_RADOSGW_RADOS
class VaultRequestCR final : public RGWCoroutine {
  CephContext* cct;
  RGWHTTPManager* http_manager;
  RGWVaultConfig config;
  std::string method;
  std::string path;
  std::string postdata;
  bufferlist* response;
  std::unique_ptr<BoundedVaultResponse> request;

public:
  VaultRequestCR(CephContext* cct, RGWHTTPManager* http_manager,
                RGWVaultConfig config, const char* method, std::string path,
                std::string postdata, bufferlist* response)
    : RGWCoroutine(cct), cct(cct), http_manager(http_manager),
      config(std::move(config)),
      method(method ? method : ""),
      path(std::move(path)), postdata(std::move(postdata)), response(response) {}

  int operate(const DoutPrefixProvider* dpp) override
  {
    reenter(this) {
      if (!cct || !http_manager || method.empty() || path.empty() || !response ||
          config.address.empty()) {
        return set_cr_error(-EINVAL);
      }

      if (!request) {
        yield {
          std::string url = config.address;
          append_url(url, config.prefix);
          append_url(url, path);
          std::string token;
          if (config.auth == "token") {
            const int ret = load_token(config.token_file, &token);
            if (ret < 0) {
              return set_cr_error(ret);
            }
          }

          RGWEndpoint endpoint;
          endpoint.set_url(url);
          if (config.reject_prohibited_addresses) {
            endpoint.set_address_policy(
              RGWEndpointAddressPolicy::reject_prohibited);
          }
          request = std::make_unique<BoundedVaultResponse>(
            cct, method, endpoint, response, 128 * 1024);
          if (!postdata.empty()) {
            request->set_post_data(postdata);
            request->set_send_length(postdata.length());
            request->append_header("Content-Type", "application/json");
          }
          if (!token.empty()) {
            request->append_header("X-Vault-Token", token);
          }
          if (!config.namespace_name.empty()) {
            request->append_header("X-Vault-Namespace", config.namespace_name);
          }
          request->set_verify_ssl(config.verify_ssl);
          if (!config.ssl_cacert.empty()) request->set_ca_path(config.ssl_cacert);
          if (!config.ssl_clientcert.empty()) request->set_client_cert(config.ssl_clientcert);
          if (!config.ssl_clientkey.empty()) request->set_client_key(config.ssl_clientkey);
          init_new_io(request.get());
          const int ret = http_manager->add_request(request.get());
          if (ret < 0) {
            return set_cr_error(ret);
          }
          return io_block(0);
        }
      }
      if (!request->is_done()) {
        return set_cr_error(-EIO);
      }
      if (is_vault_auth_failure(request->get_http_status())) {
        return set_cr_error(-EACCES);
      }
      const int ret = request->get_req_retcode();
      return ret < 0 ? set_cr_error(ret) : set_cr_done();
    }
    return 0;
  }
};
#endif

int load_token(const std::string& path, std::string* token)
{
  if (!token) {
    return -EINVAL;
  }
  token->clear();
  if (path.empty()) {
    return -EINVAL;
  }
  const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    return -errno;
  }
  struct stat token_st;
  if (fstat(fd, &token_st) != 0) {
    const int error = -errno;
    close(fd);
    return error;
  }
  if (!S_ISREG(token_st.st_mode) ||
      token_st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
    close(fd);
    return -EACCES;
  }

  char buf[2048];
  const int ret = safe_read(fd, buf, sizeof(buf));
  const int close_ret = close(fd);
  const int close_error = errno;
  if (ret < 0) {
    ::ceph::crypto::zeroize_for_security(buf, sizeof(buf));
    return ret;
  }
  if (close_ret < 0) {
    ::ceph::crypto::zeroize_for_security(buf, sizeof(buf));
    return -close_error;
  }
  int length = ret;
  while (length && std::isspace(static_cast<unsigned char>(buf[length - 1]))) {
    --length;
  }
  if (length == 0) {
    ::ceph::crypto::zeroize_for_security(buf, sizeof(buf));
    return -EACCES;
  }
  if (std::any_of(buf, buf + length, [](unsigned char c) {
        return c < 0x20 || c == 0x7f;
      })) {
    ::ceph::crypto::zeroize_for_security(buf, sizeof(buf));
    return -EACCES;
  }
  token->assign(buf, static_cast<size_t>(length));
  ::ceph::crypto::zeroize_for_security(buf, sizeof(buf));
  return 0;
}

} // anonymous namespace

int rgw::vault::testing::load_token(const std::string& path,
                                    std::string* token)
{
  return ::load_token(path, token);
}

int RGWVaultClient::request(const DoutPrefixProvider* dpp, const char* method,
                            std::string_view path,
                            const std::string& postdata, optional_yield y,
                            bufferlist& response) const
{
  if (!cct || !method || !*method || path.empty()) {
    return -EINVAL;
  }

  std::string token;
  if (config.auth == "token") {
    const int ret = load_token(config.token_file, &token);
    if (ret < 0) {
      return ret;
    }
  }
  if (config.address.empty()) {
    return -EINVAL;
  }

  std::string url = config.address;
  append_url(url, config.prefix);
  append_url(url, path);

  static constexpr size_t max_response_size = 128 * 1024;
  RGWEndpoint endpoint;
  endpoint.set_url(url);
  if (config.reject_prohibited_addresses) {
    endpoint.set_address_policy(RGWEndpointAddressPolicy::reject_prohibited);
  }
  BoundedVaultResponse request(cct, method, endpoint, &response,
                               max_response_size);
  if (!postdata.empty()) {
    request.set_post_data(postdata);
    request.set_send_length(postdata.length());
    request.append_header("Content-Type", "application/json");
  }
  if (!token.empty()) {
    request.append_header("X-Vault-Token", token);
  }
  if (!config.namespace_name.empty()) {
    request.append_header("X-Vault-Namespace", config.namespace_name);
  }
  request.set_verify_ssl(config.verify_ssl);
  if (!config.ssl_cacert.empty()) {
    request.set_ca_path(config.ssl_cacert);
  }
  if (!config.ssl_clientcert.empty()) {
    request.set_client_cert(config.ssl_clientcert);
  }
  if (!config.ssl_clientkey.empty()) {
    request.set_client_key(config.ssl_clientkey);
  }

  const int ret = request.process(dpp, y);
  if (is_vault_auth_failure(request.get_http_status())) {
    return -EACCES;
  }
  return ret;
}

#ifdef WITH_RADOSGW_RADOS
RGWCoroutine* RGWVaultClient::request_async(RGWHTTPManager* http_manager,
                                             const char* method,
                                             std::string_view path,
                                             std::string postdata,
                                             bufferlist* response) const
{
  if (!cct || !http_manager || !method || !*method || path.empty() ||
      !response) {
    return nullptr;
  }
  return new VaultRequestCR(cct, http_manager, config, method, std::string(path),
                            std::move(postdata), response);
}
#endif
