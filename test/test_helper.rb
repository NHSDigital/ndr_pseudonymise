ENV['RAILS_ENV'] = 'test'
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'active_support/deprecation'
begin
  require 'active_support/deprecator'
rescue LoadError
  # Ignore error: 'active_support/deprecator' is not defined on active_support 7.0
end
require 'active_support/test_case'

require 'ndr_pseudonymise'
require 'minitest/autorun'
require 'mocha/minitest'
