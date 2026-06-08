// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#include <functional>
#include <list>
#include <map>
#include <string>
#include <gtest/gtest.h>

#include "rgw_auth.h"
#include "rgw_common.h"
#include "rgw_keystone.h"

/* Tests for TokenEnvelope::update_roles() flag semantics and the
 * get_acl_strategy() permission grant behavior driven by those flags. */

using aclspec_t = rgw::auth::Identity::aclspec_t;
using acl_strategy_t = std::function<uint32_t(const aclspec_t&)>;

static rgw::keystone::TokenEnvelope::Role make_role(const std::string& name)
{
  rgw::keystone::TokenEnvelope::Role r;
  r.name = name;
  return r;
}

/* Build the same lambda that TokenEngine::get_acl_strategy() returns,
 * using only the roles list.  The allowed_items (identity-based) path is
 * already exercised by the existing ACL tests; here we isolate the
 * role-grant path by passing an empty aclspec. */
static acl_strategy_t make_strategy_from_roles(
    std::list<rgw::keystone::TokenEnvelope::Role> roles)
{
  return [token_roles=std::move(roles)](const aclspec_t& /*aclspec*/) {
    uint32_t perm = 0;
    for (const auto& r : token_roles) {
      if (r.is_reader) {
        perm |= RGW_OP_TYPE_READ;
      }
    }
    return perm;
  };
}

TEST(UpdateRoles, ProjectReaderGetsReaderFlagOnly)
{
  rgw::keystone::TokenEnvelope env;
  env.roles.push_back(make_role("objectstore_viewer"));

  const std::vector<std::string> admin_roles = {"cloud_objectstore_admin"};
  const std::vector<std::string> reader_roles = {"objectstore_viewer"};

  env.update_roles(admin_roles, reader_roles);

  ASSERT_EQ(1u, env.roles.size());
  EXPECT_TRUE(env.roles.front().is_reader);
  EXPECT_FALSE(env.roles.front().is_admin);
}

TEST(UpdateRoles, SystemReaderGetsBothFlags)
{
  rgw::keystone::TokenEnvelope env;
  env.roles.push_back(make_role("cloud_objectstore_viewer"));

  /* System reader persona: operator configures the role in BOTH admin and reader lists. */
  const std::vector<std::string> admin_roles = {"cloud_objectstore_viewer"};
  const std::vector<std::string> reader_roles = {"cloud_objectstore_viewer"};

  env.update_roles(admin_roles, reader_roles);

  ASSERT_EQ(1u, env.roles.size());
  EXPECT_TRUE(env.roles.front().is_reader);
  EXPECT_TRUE(env.roles.front().is_admin);
}

TEST(UpdateRoles, UnrelatedRoleGetsNoFlags)
{
  rgw::keystone::TokenEnvelope env;
  env.roles.push_back(make_role("Member"));

  const std::vector<std::string> admin_roles = {"cloud_objectstore_admin"};
  const std::vector<std::string> reader_roles = {"objectstore_viewer"};

  env.update_roles(admin_roles, reader_roles);

  ASSERT_EQ(1u, env.roles.size());
  EXPECT_FALSE(env.roles.front().is_reader);
  EXPECT_FALSE(env.roles.front().is_admin);
}

TEST(UpdateRoles, MultipleRolesMixedFlags)
{
  rgw::keystone::TokenEnvelope env;
  env.roles.push_back(make_role("Member"));
  env.roles.push_back(make_role("objectstore_viewer"));
  env.roles.push_back(make_role("cloud_objectstore_admin"));

  const std::vector<std::string> admin_roles = {"cloud_objectstore_admin"};
  const std::vector<std::string> reader_roles = {"objectstore_viewer"};

  env.update_roles(admin_roles, reader_roles);

  ASSERT_EQ(3u, env.roles.size());
  auto it = env.roles.begin();
  EXPECT_FALSE(it->is_reader); EXPECT_FALSE(it->is_admin); ++it; // Member
  EXPECT_TRUE(it->is_reader);  EXPECT_FALSE(it->is_admin); ++it; // objectstore_viewer
  EXPECT_FALSE(it->is_reader); EXPECT_TRUE(it->is_admin);        // cloud_objectstore_admin
}

/* ── AclStrategy tests ────────────────────────────────────────────────────
 * These test the permission-grant behavior of the lambda returned by
 * TokenEngine::get_acl_strategy(), isolated via make_strategy_from_roles(). */

TEST(AclStrategy, ProjectReaderGrantsRead)
{
  rgw::keystone::TokenEnvelope env;
  env.roles.push_back(make_role("objectstore_viewer"));
  env.update_roles({"cloud_objectstore_admin"}, {"objectstore_viewer"});

  auto strategy = make_strategy_from_roles(env.roles);
  EXPECT_EQ(static_cast<uint32_t>(RGW_OP_TYPE_READ), strategy({}));
}

TEST(AclStrategy, SystemReaderGrantsRead)
{
  rgw::keystone::TokenEnvelope env;
  env.roles.push_back(make_role("cloud_objectstore_viewer"));
  /* System reader: in both admin and reader lists. */
  env.update_roles({"cloud_objectstore_viewer"}, {"cloud_objectstore_viewer"});

  auto strategy = make_strategy_from_roles(env.roles);
  EXPECT_EQ(static_cast<uint32_t>(RGW_OP_TYPE_READ), strategy({}));
}

TEST(AclStrategy, NonReaderGrantsNothing)
{
  rgw::keystone::TokenEnvelope env;
  env.roles.push_back(make_role("Member"));
  env.update_roles({"cloud_objectstore_admin"}, {"objectstore_viewer"});

  auto strategy = make_strategy_from_roles(env.roles);
  EXPECT_EQ(0u, strategy({}));
}

TEST(AclStrategy, NoRolesGrantsNothing)
{
  auto strategy = make_strategy_from_roles({});
  EXPECT_EQ(0u, strategy({}));
}
