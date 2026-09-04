// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>

#include "rgw_cr_rest.h"
#include "rgw_common.h"

class RGWRESTConn;

namespace rgw::sync::s3 {

using HeaderPolicy = std::function<void(
  const DoutPrefixProvider*, const rgw_rest_obj&,
  std::map<std::string, std::string>*)>;

enum class WriteErrorPolicy { preserve, retry_marker_ignored };

struct SourceProperties {
  ceph::real_time mtime;
  std::string etag;
  uint32_t zone_short_id{0};
  uint64_t pg_ver{0};
};

// HeaderPolicy and send_ready() retain the existing stream-writer void
// contract. REST request preparation records signing failures and reports them
// from send() before submitting the request.

class Target {
public:
  virtual ~Target() = default;
  virtual int init_put(const rgw_obj& dest_obj,
                       RGWRESTStreamS3PutObj** request) = 0;
  virtual void send_ready(const DoutPrefixProvider* dpp,
                          RGWRESTStreamS3PutObj* request,
                          const rgw_rest_obj& source,
                          const std::map<std::string, std::string>& headers) = 0;
  virtual RGWCoroutine* delete_object(CephContext* cct,
                                      RGWHTTPManager* http_manager,
                                      std::string path,
                                      bool* not_found,
                                      int* http_status = nullptr) = 0;
};

// Adapter for an existing REST connection. The shared ownership is retained by
// every PUT/DELETE operation through completion.
std::shared_ptr<Target> make_rest_target(std::shared_ptr<RGWRESTConn> conn);

// Shared source-zone reader for plain and multipart S3 transfers. The source
// connection remains owned by the data-sync context for the reader lifetime.
class StreamGetCRF : public RGWStreamReadHTTPResourceCRF {
  RGWRESTConn* conn;
  rgw_obj src_obj;
  SourceProperties properties;
  RGWRESTConn::get_obj_params request_params;

public:
  StreamGetCRF(CephContext* cct, RGWCoroutinesEnv* env,
               RGWCoroutine* caller, RGWHTTPManager* http_manager,
               RGWRESTConn* conn, rgw_obj src_obj,
               SourceProperties properties);

  int init(const DoutPrefixProvider* dpp) override;
  int decode_rest_obj(const DoutPrefixProvider* dpp,
                      std::map<std::string, std::string>& headers,
                      bufferlist& extra_data) override;
  bool need_extra_data() override;
};

int decode_rest_obj(const DoutPrefixProvider* dpp,
                    const std::map<std::string, bufferlist>& attrs,
                    const std::map<std::string, std::string>& headers,
                    rgw_rest_obj* info);

// Shared plain-object S3 writer. Target selection, endpoint validation,
// credentials, object mapping and metadata policy remain adapter concerns.
class StreamPutCRF : public RGWStreamWriteHTTPResourceCRF {
  std::shared_ptr<Target> target;
  rgw_obj dest_obj;
  HeaderPolicy header_policy;
  WriteErrorPolicy error_policy;

public:
  StreamPutCRF(CephContext* cct, RGWCoroutinesEnv* env,
               RGWCoroutine* caller, RGWHTTPManager* http_manager,
               std::shared_ptr<Target> target, rgw_obj dest_obj,
               HeaderPolicy header_policy,
               WriteErrorPolicy error_policy = WriteErrorPolicy::preserve);

  int init() override;
  int send() override;
  int write(bufferlist& data, bool* need_retry) override;
  int drain_writes(bool* need_retry) override;
  void send_ready(const DoutPrefixProvider* dpp,
                  const rgw_rest_obj& rest_obj) override;
};

RGWCoroutine* delete_object(CephContext* cct, std::shared_ptr<Target> target,
                            RGWHTTPManager* http_manager,
                            std::string path, int* http_status = nullptr);

int normalize_delete_result(int result, bool remote_not_found);
int normalize_write_result(int result);

} // namespace rgw::sync::s3
