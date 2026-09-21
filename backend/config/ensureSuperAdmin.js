const bcrypt = require("bcryptjs");
const User = require("../models/User");

// Keeps the super admin in sync with ADMIN_USERNAME / ADMIN_PASSWORD.
async function ensureSuperAdmin() {
  const { ADMIN_USERNAME, ADMIN_PASSWORD } = process.env;

  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    console.warn("⚠ ADMIN_USERNAME / ADMIN_PASSWORD not set, skipping super admin setup");
    return;
  }

  const existing = await User.findOne({ role: "super_admin" });

  if (!existing) {
    await User.create({
      username: ADMIN_USERNAME,
      password: await bcrypt.hash(ADMIN_PASSWORD, 10),
      role: "super_admin",
    });
    console.log("✓ Super admin created");
    return;
  }

  const passwordMatches = await bcrypt.compare(ADMIN_PASSWORD, existing.password);
  if (existing.username !== ADMIN_USERNAME || !passwordMatches) {
    existing.username = ADMIN_USERNAME;
    existing.password = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await existing.save();
    console.log("✓ Super admin updated");
  }
}

module.exports = ensureSuperAdmin;
