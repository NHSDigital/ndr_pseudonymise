ENV['RAILS_ENV'] = 'test'
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
$LOAD_PATH.unshift File.expand_path('../script/ndr_encrypt/lib', __dir__)

require 'active_support/test_case'

require 'ndr_pseudonymise'
require 'minitest/autorun'
require 'mocha/minitest'
