#include <gtest/gtest.h>
#include "common/CephContext.h"
#include "common/config.h"
#include "rgw_common.h"
#include "rgw_auth.h"

// Mock Identity
namespace rgw {
namespace auth {
class MockIdentity : public Identity {
public:
  bool admin;
  MockIdentity(bool _admin) : admin(_admin) {}

  ACLOwner get_aclowner() const override { return {}; }
  uint32_t get_perms_from_aclspec(const DoutPrefixProvider* dpp, const aclspec_t& aclspec) const override { return 0; }
  bool is_admin() const override { return admin; }
  bool is_owner_of(const rgw_owner& uid) const override { return false; }
  bool is_root() const override { return false; }
  uint32_t get_perm_mask() const override { return 0; }
  bool is_identity(const Principal& p) const override { return false; }
  void to_str(std::ostream& out) const override { out << "mock"; }
  uint32_t get_identity_type() const override { return TYPE_RGW; }
  std::optional<rgw::ARN> get_caller_identity() const override { return std::nullopt; }
  std::string get_acct_name() const override { return "mock"; }
  std::string get_subuser() const override { return ""; }
  const std::string& get_tenant() const override { static std::string t; return t; }
  const std::optional<RGWAccountInfo>& get_account() const override { static std::optional<RGWAccountInfo> a; return a; }
};
}
}

TEST(BucketWriteProtection, CheckProtection) {
  auto cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);
  cct->_conf.set_val_or_die("rgw_bucket_write_protection_enabled", "true");

  RGWBucketInfo bucket_info;
  bucket_info.write_protected = false;

  rgw::auth::MockIdentity admin_identity(true);
  rgw::auth::MockIdentity user_identity(false);

  // Case 1: Not protected, normal user, WRITE permission -> Allowed (true)
  EXPECT_TRUE(rgw_check_bucket_write_protection(nullptr, cct, bucket_info, user_identity, RGW_PERM_WRITE));

  // Enable Protection
  bucket_info.write_protected = true;

  // Case 2: Protected, normal user, READ permission -> Allowed (true)
  EXPECT_TRUE(rgw_check_bucket_write_protection(nullptr, cct, bucket_info, user_identity, RGW_PERM_READ));

  // Case 3: Protected, normal user, WRITE -> Blocked (false)
  EXPECT_FALSE(rgw_check_bucket_write_protection(nullptr, cct, bucket_info, user_identity, RGW_PERM_WRITE));

  // Case 4: Protected, admin user, WRITE -> Allowed (true)
  EXPECT_TRUE(rgw_check_bucket_write_protection(nullptr, cct, bucket_info, admin_identity, RGW_PERM_WRITE));

  cct->put();
}
