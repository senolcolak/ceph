// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "include/buffer.h"
#include "rgw_http_client.h"

class CephContext;
class DoutPrefixProvider;
class RGWCoroutine;

struct RGWVaultConfig {
  std::string address;
  std::string auth;
  std::string token_file;
  std::string namespace_name;
  std::string prefix;
  std::string ssl_cacert;
  std::string ssl_clientcert;
  std::string ssl_clientkey;
  bool verify_ssl{true};
};

class RGWVaultClient {
  CephContext* cct;
  RGWVaultConfig config;

public:
  RGWVaultClient(CephContext* cct, RGWVaultConfig config)
    : cct(cct), config(std::move(config)) {}

  int request(const DoutPrefixProvider* dpp, const char* method,
              std::string_view path, const std::string& postdata,
              optional_yield y, bufferlist& response) const;
  RGWCoroutine* request_async(const char* method, std::string_view path,
                              std::string postdata,
                              bufferlist* response) const;
};
