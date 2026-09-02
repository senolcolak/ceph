// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include <cerrno>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "rgw_sync_s3_transfer.h"

namespace s3 = rgw::sync::s3;

namespace {

class DoneCR final : public RGWCoroutine {
  int result;
public:
  explicit DoneCR(CephContext* cct, int result = 0)
    : RGWCoroutine(cct), result(result) {}

  int operate(const DoutPrefixProvider*) override
  {
    return result < 0 ? set_cr_error(result) : set_cr_done();
  }
};

class FakeTarget final : public s3::Target {
public:
  int put_result{-ECONNREFUSED};
  bool delete_called{false};
  std::string deleted_path;
  int delete_result{0};
  bool delete_not_found{false};

  int init_put(const rgw_obj&, RGWRESTStreamS3PutObj** request) override
  {
    *request = nullptr;
    return put_result;
  }

  void send_ready(const DoutPrefixProvider*, RGWRESTStreamS3PutObj*,
                  const rgw_rest_obj&,
                  const std::map<std::string, std::string>&) override
  {
  }

  RGWCoroutine* delete_object(CephContext* cct, RGWHTTPManager*,
                              std::string path, bool* not_found) override
  {
    delete_called = true;
    deleted_path = std::move(path);
    if (not_found) {
      *not_found = delete_not_found;
    }
    return new DoneCR(cct, delete_result);
  }
};

TEST(RGWSyncS3Transfer, PropagatesPutInitializationError)
{
  auto target = std::make_shared<FakeTarget>();
  s3::StreamPutCRF writer(nullptr, nullptr, nullptr, nullptr, target,
                          rgw_obj{}, {});
  EXPECT_EQ(-ECONNREFUSED, writer.init());
}

TEST(RGWSyncS3Transfer, NormalizesMarkerIgnoredWriteErrors)
{
  EXPECT_EQ(0, s3::normalize_write_result(0));
  EXPECT_EQ(-EIO, s3::normalize_write_result(-ENOENT));
  EXPECT_EQ(-EIO, s3::normalize_write_result(-EPERM));
  EXPECT_EQ(-EIO, s3::normalize_write_result(-EACCES));
  EXPECT_EQ(-EIO, s3::normalize_write_result(-EBUSY));
  EXPECT_EQ(-EIO, s3::normalize_write_result(-EAGAIN));
  EXPECT_EQ(-ECONNREFUSED, s3::normalize_write_result(-ECONNREFUSED));

  auto target = std::make_shared<FakeTarget>();
  target->put_result = -ENOENT;
  s3::StreamPutCRF writer(nullptr, nullptr, nullptr, nullptr, target,
                          rgw_obj{}, {},
                          s3::WriteErrorPolicy::retry_marker_ignored);
  EXPECT_EQ(-EIO, writer.init());

  s3::StreamPutCRF compatible_writer(
    nullptr, nullptr, nullptr, nullptr, target, rgw_obj{}, {});
  EXPECT_EQ(-ENOENT, compatible_writer.init());
}

TEST(RGWSyncS3Transfer, RejectsSuccessWithoutRequest)
{
  auto target = std::make_shared<FakeTarget>();
  target->put_result = 0;
  s3::StreamPutCRF writer(nullptr, nullptr, nullptr, nullptr, target,
                          rgw_obj{}, {});
  EXPECT_EQ(-EIO, writer.init());
}

TEST(RGWSyncS3Transfer, RejectsNullTarget)
{
  s3::StreamPutCRF writer(nullptr, nullptr, nullptr, nullptr, nullptr,
                          rgw_obj{}, {});
  EXPECT_EQ(-EINVAL, writer.init());
}

TEST(RGWSyncS3Transfer, RetainsTargetForWriterLifetime)
{
  auto target = std::make_shared<FakeTarget>();
  std::weak_ptr<s3::Target> weak = target;
  {
    s3::StreamPutCRF writer(nullptr, nullptr, nullptr, nullptr, target,
                            rgw_obj{}, {});
    target.reset();
    EXPECT_FALSE(weak.expired());
  }
  EXPECT_TRUE(weak.expired());
}

TEST(RGWSyncS3Transfer, DeleteDefersTargetCallAndRetainsTarget)
{
  auto target = std::make_shared<FakeTarget>();
  auto* operation = s3::delete_object(g_ceph_context, target, nullptr,
                                      "bucket/a%20b");
  ASSERT_NE(nullptr, operation);
  EXPECT_FALSE(target->delete_called);
  std::weak_ptr<s3::Target> weak = target;
  target.reset();
  EXPECT_FALSE(weak.expired());
  operation->put();
  EXPECT_TRUE(weak.expired());
}

TEST(RGWSyncS3Transfer, RunsDeleteCoroutineAndPropagatesResult)
{
  auto target = std::make_shared<FakeTarget>();
  auto* operation = s3::delete_object(g_ceph_context, target, nullptr,
                                      "bucket/key");
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(0, manager.run(&dpp, operation));
  EXPECT_TRUE(target->delete_called);
  EXPECT_EQ("bucket/key", target->deleted_path);
}

TEST(RGWSyncS3Transfer, OnlyConfirmedNotFoundIsIdempotent)
{
  auto target = std::make_shared<FakeTarget>();
  target->delete_result = -ENOENT;
  target->delete_not_found = true;
  auto* operation = s3::delete_object(g_ceph_context, target, nullptr,
                                      "bucket/key");
  RGWCoroutinesManager manager(g_ceph_context, nullptr);
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(0, manager.run(&dpp, operation));

  target = std::make_shared<FakeTarget>();
  target->delete_result = -ENOENT;
  operation = s3::delete_object(g_ceph_context, target, nullptr,
                                "bucket/key");
  EXPECT_EQ(-ENOENT, manager.run(&dpp, operation));
}

TEST(RGWSyncS3Transfer, NormalizesOnlyConfirmedRemoteNotFound)
{
  EXPECT_EQ(0, s3::normalize_delete_result(-ENOENT, true));
  EXPECT_EQ(-ENOENT, s3::normalize_delete_result(-ENOENT, false));
  EXPECT_EQ(-EIO, s3::normalize_delete_result(-EIO, true));
}

TEST(RGWSyncS3Transfer, SourceReaderRejectsNullConnection)
{
  auto reader = std::make_unique<s3::StreamGetCRF>(
    g_ceph_context, nullptr, nullptr, nullptr, nullptr, rgw_obj{},
    s3::SourceProperties{});
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};
  EXPECT_EQ(-EINVAL, reader->init(&dpp));
}

TEST(RGWSyncS3Transfer, DecodesSourceObjectHeaders)
{
  std::map<std::string, bufferlist> attrs;
  std::map<std::string, std::string> headers{
    {"CONTENT_TYPE", "application/octet-stream"},
    {"RGWX_OBJECT_SIZE", "4096"},
  };
  rgw_rest_obj object;
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};

  EXPECT_EQ(-EINVAL, s3::decode_rest_obj(&dpp, attrs, headers, nullptr));
  ASSERT_EQ(0, s3::decode_rest_obj(&dpp, attrs, headers, &object));
  EXPECT_EQ(4096u, object.content_len);
  EXPECT_EQ("application/octet-stream", object.attrs["CONTENT_TYPE"]);
  EXPECT_EQ(0u, object.attrs.count("RGWX_OBJECT_SIZE"));
}

TEST(RGWSyncS3Transfer, RejectsCorruptSourceAcl)
{
  std::map<std::string, bufferlist> attrs;
  attrs[RGW_ATTR_ACL].append("not-an-encoded-acl");
  std::map<std::string, std::string> headers;
  rgw_rest_obj object;
  NoDoutPrefix dpp{g_ceph_context, ceph_subsys_rgw};

  EXPECT_EQ(-EIO, s3::decode_rest_obj(&dpp, attrs, headers, &object));
}

} // anonymous namespace
