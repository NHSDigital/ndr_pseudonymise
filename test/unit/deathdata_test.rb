# test loading and encrypting sample death data
# https://ncr.plan.io/issues/4810

require 'test_helper'
require 'ndr_import/mapper'
# --------------------------------------------------------------------------------
class DeathDataTest < ActiveSupport::TestCase
  include NdrImport::Mapper

  # expose private methods
  public :fixed_width_columns, :mapped_line, :mapped_value, :replace_before_mapping

  attr_reader :mappings

  def stripblanks(h)
    # remove trailing whitespace in hash values
    newh = {}
    h.each do |k, v|
      newh[k] =
        if v.is_a?(String)
          v.rstrip
        elsif v.is_a?(Hash)
          stripblanks(v) # recursive call for hash of hashes
        else
          v
        end
    end

    newh
  end

  TESTDIR = File.join('test', 'unit')
  SAMPLE_SALT_BUNDLE = File.join(TESTDIR, 'salt_4810.kek')
  SAMPLE_SALT_PASSPHRASE = 'passtastic99'.freeze
  MAPPINGS_FILE = File.join(TESTDIR, 'sample_death_data.yml')
  DEATHFILE = File.join(TESTDIR, 'sample_death_data.txt')

  def setup
    NdrImport::StandardMappings.mappings =
      YAML.load_file(File.join(TESTDIR, 'standard_mappings.yml'))

    y = YAML.load_file(MAPPINGS_FILE)
    @mappings = y['cd']
    @format_spec = y['format']

    File.open(DEATHFILE, 'r') { |f| @lines = f.readlines }
    @all_records = []
    @lines.each do |line|
      # mapped_line & fixed_width_columns come from mapper.rb
      # mapped_line returns a hash, from which the values are extracted (in original insertion order)
      @all_records += [mapped_line(fixed_width_columns(line, @mappings), @mappings).values]
    end

    @salt = NdrPseudonymise::PseudonymisationSpecification.get_key_bundle(SAMPLE_SALT_BUNDLE, SAMPLE_SALT_PASSPHRASE)
  end

  test 'number_of_records' do
    assert_equal(@all_records.size, 4)
  end

  test 'core_demographics' do
    # get values of hash as a list in original insertion order
    @row = @all_records[3]

    # ** in sample_death_data.txt (derived from CD041634DUMMY.NCR),
    #    for a blank 'previoussurname' field, a '/' must be used to delimit this. **
    @pspec = NdrPseudonymise::PseudonymisationSpecification.new(@format_spec, @salt)

    assert_equal([[%w(nhsnumber 9999999492)],
                  [%w(dateofbirth 1938-05-08T00:00:00+00:00),
                   %w(postcode E58AA)]],
                 @pspec.core_demographics(@row))
  end
end
