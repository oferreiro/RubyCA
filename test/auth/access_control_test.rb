require_relative '../test_helper'
require 'core/web/auth'

# Unit tests for the shared admin access control (core/web/auth.rb).
# host_allowed? takes the allowlist as a parameter, so these run without
# Rack, the HTTP stack, or the developer's real config file.
class AccessControlTest < Minitest::Test
  def test_exact_ipv4_match
    assert host_allowed?('192.168.1.10', ['192.168.1.10'])
  end

  def test_cidr_range_containment
    assert host_allowed?('10.0.0.7', ['10.0.0.0/24'])
    assert host_allowed?('10.0.0.1', ['10.0.0.0/24', '192.168.1.1'])
  end

  def test_non_matching_ip_is_rejected
    refute host_allowed?('203.0.113.50', ['192.168.1.10'])
    refute host_allowed?('10.0.1.7', ['10.0.0.0/24'])
  end

  def test_ipv4_address_does_not_match_ipv6_allowlist_entry
    refute host_allowed?('192.168.1.10', ['::1', 'fe80::/64'])
  end

  def test_ipv6_address_does_not_match_ipv4_allowlist_entry
    refute host_allowed?('::1', ['192.168.1.0/24'])
  end

  def test_ipv6_exact_match
    assert host_allowed?('::1', ['127.0.0.1', '::1'])
    assert host_allowed?('fe80::1', ['fe80::/64'])
  end

  def test_malformed_request_address_is_rejected_not_raised
    refute host_allowed?('not-an-ip', ['192.168.1.0/24'])
    refute host_allowed?('999.999.999.999', ['192.168.1.0/24'])
  end

  def test_malformed_allowlist_entry_is_skipped_not_raised
    assert host_allowed?('192.168.1.10', ['garbage', '192.168.1.10'])
    refute host_allowed?('192.168.1.10', ['garbage'])
  end

  def test_nil_request_address_is_rejected
    refute host_allowed?(nil, ['192.168.1.0/24'])
  end

  def test_nil_allowlist_rejects_everything
    refute host_allowed?('127.0.0.1', nil)
  end

  def test_empty_allowlist_rejects_everything
    refute host_allowed?('127.0.0.1', [])
  end

  # The Settings page edits the allowlist itself, so it must never be
  # reachable without a login - even from an allowlisted address.
  def test_config_page_requires_authentication_even_from_allowed_ip
    assert admin_auth_required?('/admin/config', '127.0.0.1', ['127.0.0.1'])
    assert admin_auth_required?('/admin/config/', '127.0.0.1', ['127.0.0.1'])
    assert admin_auth_required?('/admin/configs', '127.0.0.1', ['127.0.0.1'])
    assert admin_auth_required?('/admin/configs/', '127.0.0.1', ['127.0.0.1'])
  end

  def test_other_admin_paths_still_bypass_for_allowed_ip
    refute admin_auth_required?('/admin', '127.0.0.1', ['127.0.0.1'])
    refute admin_auth_required?('/admin/certificates', '127.0.0.1', ['127.0.0.1'])
    refute admin_auth_required?('/admin/configuration', '127.0.0.1', ['127.0.0.1'])
    refute admin_auth_required?('/admin/config-ish', '127.0.0.1', ['127.0.0.1'])
  end

  def test_non_allowed_ip_still_requires_authentication
    assert admin_auth_required?('/admin/certificates', '203.0.113.50', ['127.0.0.1'])
  end

  def test_nil_path_falls_back_to_ip_rule
    refute admin_auth_required?(nil, '127.0.0.1', ['127.0.0.1'])
    assert admin_auth_required?(nil, '203.0.113.50', ['127.0.0.1'])
  end

  private

  def admin_auth_required?(path, addr, allowed_ips)
    RubyCA::Core::Web::AccessControl.admin_authentication_required?(path, addr, allowed_ips)
  end

  def host_allowed?(addr, allowed_ips)
    RubyCA::Core::Web::AccessControl.host_allowed?(addr, allowed_ips)
  end
end
