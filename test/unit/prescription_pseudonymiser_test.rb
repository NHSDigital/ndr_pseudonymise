require 'test_helper'

require 'csv'
require 'stringio'
require 'json'

require 'ndr_pseudonymise/prescription_pseudonymiser'
require 'ndr_pseudonymise/pseudonymisation_specification'
require 'rsa_aes_cbc'

class PrescriptionPseudonymiserTest < ActiveSupport::TestCase
  TESTDIR = File.join('test/unit')
  SAMPLE_DATA = File.join(TESTDIR, 'sample_prescription_data_v3.csv')
  SAMPLE_SPEC = File.join(TESTDIR, 'prescription_data_format_1.0.1.yml')
  SAMPLE_SALT = File.join(TESTDIR, 'sample_salt.yml')
  SAMPLE_SALT_BUNDLE = File.join(TESTDIR, 'sample_salt_bundle.kek')
  SAMPLE_RSA_PUB = File.join(TESTDIR, 'pseudonymise_rsa_test_3072bit_pub.pem')
  SAMPLE_RSA_PRIV = File.join(TESTDIR, 'pseudonymise_rsa_test_3072bit.pem')
  SAMPLE_SALT_PASSPHRASE = 'TestPassphraseForPseudonymisationSaltFile'.freeze

  def setup
    @format_spec = YAML.load_file(SAMPLE_SPEC)
    @salt = NdrPseudonymise::PseudonymisationSpecification.get_key_bundle(SAMPLE_SALT_BUNDLE, SAMPLE_SALT_PASSPHRASE)
    @pspec = NdrPseudonymise::PrescriptionPseudonymiser.new(@format_spec, @salt)
    @rows = CSV.read(SAMPLE_DATA)
    @row1 = @rows[1] # Exclude header row
  end

  test 'pseudonymise_csv' do
    csv_lib = CSV
    out_buff1 = StringIO.new
    @pspec.pseudonymise_csv(@rows, out_buff1)
    out_data1 = []
    out_buff1.rewind
    csv_lib.new(out_buff1).each { |row| out_data1 << row }

    @pspec = NdrPseudonymise::PrescriptionPseudonymiser.new(@format_spec, @salt) # Reset cache
    out_buff2 = StringIO.new
    File.open(SAMPLE_DATA, 'r') do |csv_file|
      @pspec.pseudonymise_csv(csv_file, out_buff2)
    end
    out_data2 = []
    out_buff2.rewind
    csv_lib.new(out_buff2).each { |row| out_data2 << row }

    # Initial file had 20 columns (including nhs_number and pat_dob)
    # Output file will have 19 columns (replacing those two with a demographics blob)
    assert_equal(@rows[0].size - 1, out_data1[-1].size)
    assert_equal(@rows[0].size - 1, out_data2[-1].size)
    # The file will have one extra row
    assert_equal(@rows.size + 1, out_data1.size)
    assert_equal(@rows.size + 1, out_data2.size)
    # All but the initial 2 (or 1) columns will be the same non-disclosive clinical data
    assert_equal(@rows[-1][2..-1], out_data1[-1][1..-1])
    assert_equal(@rows[-1][2..-1], out_data2[-1][1..-1])
    # Different pseudonymisations will have same pseudonymised id, but different key and encrypted
    # demographics hash
    pseudo_id1, key_bundle1, demog_hash1 = out_data1[-1][0].split(/ \(|\) /)
    pseudo_id2, key_bundle2, demog_hash2 = out_data2[-1][0].split(/ \(|\) /)
    assert_equal(pseudo_id1, pseudo_id2, 'Expected same pseudonymised id')
    assert_equal(key_bundle1.size, key_bundle2.size, 'Expected same length key bundles')
    assert_not_equal(key_bundle1, key_bundle2, 'Expected different key bundles')
    assert_not_equal(demog_hash1, demog_hash2, 'Expected different encryped demographics')
  end

  test 'PseudonymisationSpecification factory class' do
    pspec2 = NdrPseudonymise::PseudonymisationSpecification.factory(@format_spec, @salt)
    assert_instance_of(NdrPseudonymise::PrescriptionPseudonymiser, pspec2)
  end
end
