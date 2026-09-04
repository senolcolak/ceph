// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
#include "rgw_vault_client.h"

#include <sys/stat.h>
#include <cctype>
#include <cerrno>

#include "common/ceph_crypto.h"
#include "common/safe_io.h"
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
  RGWVaultConfig config;
  std::string method;
  std::string path;
  std::string postdata;
  bufferlist* response;
  std::unique_ptr<BoundedVaultResponse> request;

public:
  VaultRequestCR(CephContext* cct, RGWVaultConfig config, const char* method,
                std::string path, std::string postdata, bufferlist* response)
    : RGWCoroutine(cct), cct(cct), config(std::move(config)),
      method(method ? method : ""),
      path(std::move(path)), postdata(std::move(postdata)), response(response) {}

  int operate(const DoutPrefixProvider* dpp) override
  {
    reenter(this) {
      if (!cct || method.empty() || path.empty() || !response ||
          config.address.empty()) {
        return set_cr_error(-EINVAL);
      }

      if (!request) {
        {
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
          const int ret = RGWHTTP::send(request.get());
          if (ret < 0) {
            return set_cr_error(ret);
          }
        }
      }
      while (!request->is_done()) {
        yield wait(utime_t{0, 10000000});
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
  struct stat token_st;
  if (path.empty()) {
    return -EINVAL;
  }
  if (stat(path.c_str(), &token_st) != 0) {
    return -ENOENT;
  }
  if (token_st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
    return -EACCES;
  }

  char buf[2048];
  const int ret = safe_read_file("", path.c_str(), buf, sizeof(buf));
  if (ret < 0) {
    ::ceph::crypto::zeroize_for_security(buf, sizeof(buf));
    return ret;
  }
  int length = ret;
  while (length && std::isspace(static_cast<unsigned char>(buf[length - 1]))) {
    --length;
  }
  token->assign(buf, static_cast<size_t>(length));
  ::ceph::crypto::zeroize_for_security(buf, sizeof(buf));
  return length;
}

} // anonymous namespace

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
RGWCoroutine* RGWVaultClient::request_async(const char* method,
                                             std::string_view path,
                                             std::string postdata,
                                             bufferlist* response) const
{
  if (!cct || !method || !*method || path.empty() || !response) {
    return nullptr;
  }
  return new VaultRequestCR(cct, config, method, std::string(path),
                            std::move(postdata), response);
}
#endif
