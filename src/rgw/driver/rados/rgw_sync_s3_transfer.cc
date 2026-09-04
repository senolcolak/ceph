// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include "rgw_sync_s3_transfer.h"

#include <cerrno>
#include <cstdlib>
#include <memory>
#include <utility>

#include <boost/asio/yield.hpp>

#include "rgw_acl.h"
#include "rgw_rest_conn.h"

namespace rgw::sync::s3 {
namespace {

class RESTTarget final : public Target {
  std::shared_ptr<RGWRESTConn> conn;

public:
  explicit RESTTarget(std::shared_ptr<RGWRESTConn> conn)
    : conn(std::move(conn)) {}

  int init_put(const rgw_obj& dest_obj,
               RGWRESTStreamS3PutObj** request) override
  {
    return conn->put_obj_send_init(dest_obj, nullptr, request);
  }

  void send_ready(const DoutPrefixProvider* dpp,
                  RGWRESTStreamS3PutObj* request,
                  const rgw_rest_obj& source,
                  const std::map<std::string, std::string>& headers) override
  {
    request->set_send_length(source.content_len);
    RGWAccessControlPolicy policy;
    request->send_ready(dpp, conn->get_credentials(), headers, policy);
  }

  RGWCoroutine* delete_object(CephContext* cct,
                              RGWHTTPManager* http_manager,
                              std::string path, bool* not_found,
                              int* http_status) override
  {
    return new RGWDeleteRESTResourceCR(cct, conn.get(), http_manager,
                                       std::move(path), nullptr, not_found,
                                       http_status);
  }
};

} // anonymous namespace

int decode_rest_obj(const DoutPrefixProvider* dpp,
                    const std::map<std::string, bufferlist>& attrs,
                    const std::map<std::string, std::string>& headers,
                    rgw_rest_obj* info)
{
  if (!info) {
    return -EINVAL;
  }
  for (const auto& [name, value] : headers) {
    if (name == "RGWX_OBJECT_SIZE") {
      info->content_len = std::atoi(value.c_str());
    } else {
      info->attrs[name] = value;
    }
  }

  auto acl = attrs.find(RGW_ATTR_ACL);
  if (acl == attrs.end()) {
    ldpp_dout(dpp, 0) << "WARNING: acl attrs not provided" << dendl;
    return 0;
  }

  auto iter = acl->second.cbegin();
  try {
    info->acls.decode(iter);
  } catch (const buffer::error&) {
    ldpp_dout(dpp, 0) << "ERROR: failed to decode policy from attrs"
                      << dendl;
    return -EIO;
  }
  return 0;
}

StreamGetCRF::StreamGetCRF(CephContext* cct, RGWCoroutinesEnv* env,
                           RGWCoroutine* caller,
                           RGWHTTPManager* http_manager,
                           RGWRESTConn* conn, rgw_obj src_obj,
                           SourceProperties properties)
  : RGWStreamReadHTTPResourceCRF(cct, env, caller, http_manager,
                                 src_obj.key),
    conn(conn),
    src_obj(std::move(src_obj)),
    properties(std::move(properties))
{
}

int StreamGetCRF::init(const DoutPrefixProvider* dpp)
{
  if (!conn) {
    return -EINVAL;
  }
  request_params.get_op = true;
  request_params.prepend_metadata = true;
  request_params.unmod_ptr = &properties.mtime;
  request_params.etag = properties.etag;
  request_params.mod_zone_id = properties.zone_short_id;
  request_params.mod_pg_ver = properties.pg_ver;
  if (range.is_set) {
    request_params.range_is_set = true;
    request_params.range_start = range.ofs;
    request_params.range_end = range.ofs + range.size - 1;
  }

  RGWRESTStreamRWRequest* request = nullptr;
  const int result = conn->get_obj(dpp, src_obj, request_params, false,
                                   &request);
  if (result < 0 || !request) {
    ldpp_dout(dpp, 0) << "ERROR: " << __func__
                      << "(): conn->get_obj() returned result=" << result
                      << dendl;
    return result < 0 ? result : -EIO;
  }
  set_req(request);
  return RGWStreamReadHTTPResourceCRF::init(dpp);
}

int StreamGetCRF::decode_rest_obj(
  const DoutPrefixProvider* dpp,
  std::map<std::string, std::string>& headers, bufferlist& extra_data)
{
  std::map<std::string, bufferlist> attrs;
  ldpp_dout(dpp, 20) << __func__ << ": headers=" << headers
                     << " extra_data.length()=" << extra_data.length()
                     << dendl;
  if (extra_data.length() > 0) {
    JSONParser parser;
    if (!parser.parse(extra_data.c_str(), extra_data.length())) {
      ldpp_dout(dpp, 0)
        << "ERROR: failed to parse response extra data. len="
        << extra_data.length() << dendl;
      return -EIO;
    }
    JSONDecoder::decode_json("attrs", attrs, &parser);
  }
  return rgw::sync::s3::decode_rest_obj(dpp, attrs, headers, &rest_obj);
}

bool StreamGetCRF::need_extra_data()
{
  return true;
}

class DeleteCR final : public RGWCoroutine {
  std::shared_ptr<Target> target;
  RGWHTTPManager* http_manager;
  std::string path;
  bool not_found{false};
  int http_status{0};
  int* http_status_out{nullptr};
  std::unique_ptr<RGWCoroutine> operation;

public:
  DeleteCR(CephContext* cct, std::shared_ptr<Target> target,
           RGWHTTPManager* http_manager, std::string path,
           int* http_status_out)
    : RGWCoroutine(cct),
      target(std::move(target)),
      http_manager(http_manager),
      path(std::move(path)), http_status_out(http_status_out)
  {
  }

  int operate(const DoutPrefixProvider*) override
  {
    reenter(this) {
      if (!target) {
        return set_cr_error(-EINVAL);
      }
      operation.reset(target->delete_object(cct, http_manager,
                                            std::move(path), &not_found,
                                            &http_status));
      if (!operation) {
        return set_cr_error(-EINVAL);
      }
      yield call(operation.release());
      retcode = normalize_delete_result(retcode, not_found);
      if (http_status_out) {
        *http_status_out = http_status;
      }
      if (retcode < 0) {
        return set_cr_error(retcode);
      }
      return set_cr_done();
    }
    return 0;
  }
};

std::shared_ptr<Target> make_rest_target(std::shared_ptr<RGWRESTConn> conn)
{
  return conn ? std::make_shared<RESTTarget>(std::move(conn)) : nullptr;
}

StreamPutCRF::StreamPutCRF(CephContext* cct, RGWCoroutinesEnv* env,
                           RGWCoroutine* caller,
                           RGWHTTPManager* http_manager,
                           std::shared_ptr<Target> target, rgw_obj dest_obj,
                           HeaderPolicy header_policy,
                           WriteErrorPolicy error_policy)
  : RGWStreamWriteHTTPResourceCRF(cct, env, caller, http_manager),
    target(std::move(target)),
    dest_obj(std::move(dest_obj)),
    header_policy(std::move(header_policy)), error_policy(error_policy)
{
}

int StreamPutCRF::init()
{
  if (!target) {
    return -EINVAL;
  }
  RGWRESTStreamS3PutObj* request = nullptr;
  const int result = target->init_put(dest_obj, &request);
  if (result < 0) {
    return error_policy == WriteErrorPolicy::retry_marker_ignored ?
      normalize_write_result(result) : result;
  }
  if (request == nullptr) {
    return -EIO;
  }
  set_req(request);
  return RGWStreamWriteHTTPResourceCRF::init();
}

int StreamPutCRF::send()
{
  const int result = RGWStreamWriteHTTPResourceCRF::send();
  return error_policy == WriteErrorPolicy::retry_marker_ignored ?
    normalize_write_result(result) : result;
}

int StreamPutCRF::write(bufferlist& data, bool* need_retry)
{
  const int result = RGWStreamWriteHTTPResourceCRF::write(data, need_retry);
  return error_policy == WriteErrorPolicy::retry_marker_ignored ?
    normalize_write_result(result) : result;
}

int StreamPutCRF::drain_writes(bool* need_retry)
{
  const int result = RGWStreamWriteHTTPResourceCRF::drain_writes(need_retry);
  return error_policy == WriteErrorPolicy::retry_marker_ignored ?
    normalize_write_result(result) : result;
}

void StreamPutCRF::send_ready(const DoutPrefixProvider* dpp,
                              const rgw_rest_obj& rest_obj)
{
  auto* request = static_cast<RGWRESTStreamS3PutObj*>(req);
  std::map<std::string, std::string> headers;
  if (header_policy) {
    header_policy(dpp, rest_obj, &headers);
  }
  target->send_ready(dpp, request, rest_obj, headers);
}

RGWCoroutine* delete_object(CephContext* cct,
                            std::shared_ptr<Target> target,
                            RGWHTTPManager* http_manager,
                            std::string path, int* http_status)
{
  return new DeleteCR(cct, std::move(target), http_manager,
                      std::move(path), http_status);
}

int normalize_delete_result(int result, bool remote_not_found)
{
  return result == -ENOENT && remote_not_found ? 0 : result;
}

int normalize_write_result(int result)
{
  switch (result) {
    case -EPERM:
    case -EACCES:
    case -ENOENT:
    case -EBUSY:
    case -EAGAIN:
      return -EIO;
    default:
      return result;
  }
}

} // namespace rgw::sync::s3

#include <boost/asio/unyield.hpp>
