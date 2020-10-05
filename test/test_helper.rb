ENV['RAILS_ENV'] = 'test'
$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)

require 'active_support/test_case'

require 'ndr_pseudonymise'
require 'minitest/autorun'
require 'mocha/minitest'
