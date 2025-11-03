require 'test_helper'

require 'csv'
require 'stringio'
require 'json'

require 'ndr_pseudonymise/pseudonymisation_specification'
require 'ndr_pseudonymise/progress_printer'
require 'rsa_aes_cbc'

class PseudonymisationSpecificationTest < ActiveSupport::TestCase
  TESTDIR = File.join('test', 'unit')
  SAMPLE_DATA = File.join(TESTDIR, 'sample_data.csv')
  SAMPLE_SPEC = File.join(TESTDIR, 'sample_data_spec.yml')
  SAMPLE_SALT = File.join(TESTDIR, 'sample_salt.yml')
  SAMPLE_SALT_BUNDLE = File.join(TESTDIR, 'sample_salt_bundle.kek')
  SAMPLE_RSA_PUB = File.join(TESTDIR, 'pseudonymise_rsa_test_3072bit_pub.pem')
  SAMPLE_RSA_PRIV = File.join(TESTDIR, 'pseudonymise_rsa_test_3072bit.pem')
  TESTOUTPUT_DIR = File.join('test', 'unit', 'test_files')
  SAMPLE_SALT_PASSPHRASE = 'TestPassphraseForPseudonymisationSaltFile'.freeze

  class TestProgressLogger
    attr_reader :progress

    def initialize
      @progress = []
    end

    def log_progress(start_time, time_now, csv_row, progress, total)
      @progress << [start_time, time_now, csv_row, progress, total]
    end
  end

  def setup
    @format_spec = YAML.load_file(SAMPLE_SPEC)
    @salt = NdrPseudonymise::PseudonymisationSpecification.get_key_bundle(SAMPLE_SALT_BUNDLE, SAMPLE_SALT_PASSPHRASE)
    @pspec = NdrPseudonymise::PseudonymisationSpecification.factory(@format_spec, @salt)
    @rows = CSV.read(SAMPLE_DATA)
    @row1 = @rows[1] # Exclude header row
  end

  test 'core_demographics' do
    assert_equal([[%w(nhsnumber 1234567881)],
                  [%w(birthdate 2010-08-21), %w(postcode CB223AD)]],
                 @pspec.core_demographics(@row1))
  end

  test 'real_ids and pseudo_id' do
    real_ids = @pspec.real_ids(@row1)
    assert_equal('nhsnumber_1234567881', real_ids[0])
    assert_equal('birthdate_postcode_2010-08-21_CB223AD', real_ids[1])

    pseudo_ids = real_ids.collect { |real_id| @pspec.pseudo_id(real_id) }
    assert_equal(2, pseudo_ids.length)
    assert_match(/\A[0-9a-f]{64}\Z/, pseudo_ids[0]) # SHA-256 (256 bits) in hex
    assert_not_equal(pseudo_ids[0], pseudo_ids[1])
    assert_no_match(/1234567881/, pseudo_ids.join)
  end

  test 'all_demographics' do
    all_demog = @pspec.all_demographics(@row1)
    assert_equal(@row1[0..3], all_demog)
    assert_equal(@row1[0], @row1[0].to_i.to_s) # Ensure we have "numerical" data
    all_demog.each_with_index do |x, i|
      assert(x.is_a?(String), "Expected column #{i} with value #{x.inspect} to be a String")
    end
  end

  test 'clinical_data' do
    all_demog = @pspec.clinical_data(@row1)
    assert_equal(@row1[4..-1], all_demog)
    all_demog.each_with_index do |x, i|
      assert(x.is_a?(String), "Expected column #{i} with value #{x.inspect} to be a String")
    end
  end

  test 'safe_json' do
    assert_nothing_raised do
      @pspec.safe_json([2, '3', 'A"B\'', '', nil])
    end
    assert_raise(ArgumentError) do
      @pspec.safe_json(['key', :key])
    end
  end

  test 'encrypt_data and decrypt_data' do
    # TODO: Test encrypt and decrypt
    pseudo_id = @pspec.pseudo_id('nhsnumber_dateofbirth_BLOGGS_2013-08-21')
    partial_crypt_key = @pspec.random_key
    salt = @salt[:salt1]
    data = [2, '3', 'A"B\'', '', nil]
    data_json = @pspec.safe_json(data)
    encrypted = @pspec.encrypt_data(data_json, pseudo_id, partial_crypt_key, salt)
    # Check it's a base-64 string
    assert_match(Regexp.new('\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z'), encrypted)
    data_decrypted_json = @pspec.decrypt_data(encrypted, pseudo_id, partial_crypt_key, salt)
    assert_equal(data_json, data_decrypted_json, 'decrypt_data should return the original JSON string')
    assert_equal(data, JSON.load(data_decrypted_json), 'original data should match decrypted data')
  end

  test 'encrypt_data with different keys' do
    data = @pspec.safe_json(%w(Hello world))
    pseudo_id = @pspec.random_key
    partial_crypt_key1 = @pspec.random_key
    partial_crypt_key2 = @pspec.random_key
    encrypted1 = @pspec.encrypt_data(data, pseudo_id, partial_crypt_key1,
                                     @salt[:salt1])
    encrypted2 = @pspec.encrypt_data(data, pseudo_id, partial_crypt_key2,
                                     @salt[:salt1])
    assert_not_equal(encrypted1, encrypted2, 'Expected different partial_crypt_keys to produce different encrypted outputs')

    pseudo_id3 = @pspec.random_key
    encrypted3 = @pspec.encrypt_data(data, pseudo_id3, partial_crypt_key2,
                                     @salt[:salt1])
    assert_not_equal(encrypted2, encrypted3, 'Expected different pseudo_ids to produce different encrypted outputs')

    encrypted4 = @pspec.encrypt_data(data, pseudo_id3, partial_crypt_key2,
                                     @salt[:salt2])
    assert_not_equal(encrypted3, encrypted4, 'Expected different salt to produce different encrypted outputs')
  end

  test 'pseudonymise_row' do
    skip 'TODO: Test with / without encrypt_clinical option (here or 2 test methods)'
  end

  test 'row_errors' do
    skip 'TODO: Test validations'
    skip 'TODO: Test rows with too many columns (excluding extra blank data)'
  end

  # def encrypt
  #  require Rails.root.join('lib', 'rsa_aes_cbc.rb')
  #  self.value = RSA_AES_CBC.new($config.secrets.rsa_public_path, nil ).encrypt(self.value)
  # end

  #  if File.exists?(@private)
  #        cypher = RSA_AES_CBC.new(@public, @private)
  #        assert_equal "test", cypher.decrypt(ar.value)
  #  end

  test 'pseudonymise_csv' do
    csv_lib = CSV
    out_buff1 = StringIO.new
    @pspec.pseudonymise_csv(@rows, out_buff1)
    # File.open(File.join(TESTOUTPUT_DIR, "out_buff1_#{RUBY_VERSION}.csv"), 'w') do |f|
    #  out_buff1.rewind
    #  f << out_buff1.read
    # end
    out_data1 = []
    out_buff1.rewind
    csv_lib.new(out_buff1).each { |row| out_data1 << row }

    out_buff2 = StringIO.new
    File.open(SAMPLE_DATA, 'r') do |csv_file|
      @pspec.pseudonymise_csv(csv_file, out_buff2)
    end
    out_data2 = []
    out_buff2.rewind
    csv_lib.new(out_buff2).each { |row| out_data2 << row }

    (last_index1, last_demog1, last_clinical1) = out_data1[-3..-1]
    (last_index2, last_demog2, last_clinical2) = out_data2[-3..-1]
    if @format_spec[:encrypt_clinical]
      assert_equal(4, last_index1.size)
      assert_equal(4, last_index2.size)
    else
      assert_equal(3, last_index1.size)
      assert_equal(3, last_index2.size)
    end
    assert_equal(2, last_demog1.size)
    assert_equal(2, last_demog2.size)
    assert_equal(2, last_clinical1.size)
    assert_equal(2, last_clinical2.size)

    assert_equal(last_index1[0], last_index2[0], 'Expected same pseudonymised id')
    assert_not_equal(last_index1[1], last_index2[1], 'Expected different row_keys')
    if @format_spec[:encrypt_clinical]
      assert_not_equal(last_index1[2], last_index2[2], 'Expected different partial_crypt_key2')
      assert_not_equal(last_index1[3], last_index2[3], 'Expected different partial_crypt_key2')
    end

    assert_equal(last_index1[1], last_demog1[0], 'Expected demographics to match index on row_key')
    assert_equal(last_index1[1], last_clinical1[0], 'Expected clinical to match index on row_key')

    assert_not_equal(last_demog1[1], last_demog2[1], 'Expected different encrypted demographics across 2 sessions')
    if @format_spec[:encrypt_clinical]
      assert_not_equal(last_demog1[1], last_demog2[1], 'Expected different encrypted clinical data across 2 sessions')
    else
      assert_not_equal(last_demog1[1], last_demog2[1], 'Expected same plaintext clinical data across 2 sessions')
    end
  end

  # TODO: Check decryption / patient matching library support
  test 'pseudonymise_csv with public/private key encryption / decryption' do
    csv_lib = CSV
    out_buff1 = StringIO.new
    @pspec.pseudonymise_csv(@rows, out_buff1, SAMPLE_RSA_PUB)
    File.open(File.join(TESTOUTPUT_DIR, "out_buff1_#{RUBY_VERSION}_encrypted"), 'w') do |f|
      out_buff1.rewind
      f << out_buff1.read
    end

    # TODO: Use library support for passphrase, instead of kludge here
    nocrypt_keyfile = "#{SAMPLE_RSA_PRIV.sub(/.pem\Z/, '')}.nocrypt.pem"
    unless File.exist?(nocrypt_keyfile)
      system("openssl rsa -in #{SAMPLE_RSA_PRIV} -out #{nocrypt_keyfile}")
    end
    out_buff2 = StringIO.new
    File.open(File.join(TESTOUTPUT_DIR, "out_buff1_#{RUBY_VERSION}_encrypted"), 'r') do |crypto_file|
      @pspec.decrypt_to_csv(crypto_file, out_buff2, SAMPLE_RSA_PUB, nocrypt_keyfile)
    end
    out_data2 = []
    out_buff2.rewind
    csv_lib.new(out_buff2).each { |row| out_data2 << row }

    (last_index2, last_demog2, last_clinical2) = out_data2[-3..-1]
    if @format_spec[:encrypt_clinical]
      assert_equal(4, last_index2.size)
    else
      assert_equal(3, last_index2.size)
    end
    assert_equal(2, last_demog2.size)
    assert_equal(2, last_clinical2.size)
  end

  # Pseudonymise a CSV file (as a StringIO) rather than an array of rows
  test 'pseudonymise_csv with IO progress' do
    csv_lib = CSV
    in_buff = StringIO.new
    in_csv = csv_lib.new(in_buff)
    @rows.each { |row| in_csv << row }
    in_buff.rewind
    out_buff1 = StringIO.new
    progress_logger = TestProgressLogger.new
    @pspec.pseudonymise_csv(in_buff, out_buff1, nil, progress_logger)
    out_buff1.rewind
    # 2 header rows, 3 data rows each result in 1*3 or 2*3 output rows (depending on which
    # pseudo_ids have data)
    assert_equal(2 + 6 * 3, out_buff1.readlines.size)
    assert_equal(1, progress_logger.progress.size) # Logs every 1000 rows, and at the end
    (start_time, time_now, _csv_row, progress, total) = progress_logger.progress[0] # _csv_row isn't used
    assert(time_now >= start_time)
    assert_equal(total, progress)
  end

  # Pseudonymise a CSV file (as a StringIO) rather than an array of rows
  test 'pseudonymise_csv with File progress' do
    # Data
    csv_lib = CSV
    fname = File.join(TESTOUTPUT_DIR, "in_buff_#{RUBY_VERSION}.csv")
    File.open(fname, 'w') do |f|
      in_csv = csv_lib.new(f, row_sep: "\r\n")
      @rows.each { |row| in_csv << row }
    end
    in_file = File.open(fname, 'r')
    out_buff1 = StringIO.new
    progress_buff = StringIO.new
    @pspec.pseudonymise_csv(in_file, out_buff1, nil,
                            NdrPseudonymise::ProgressPrinter.new(progress_buff))
    progress_buff.rewind
    in_file.close
    File.delete(fname)
    out_buff1.rewind
    # 2 header rows, 3 data rows each result in 1*3 or 2*3 output rows
    # (depending on which pseudo_ids have data)
    assert_equal(2 + 6 * 3, out_buff1.readlines.size)
    assert_equal("100%\n", progress_buff.read)
  end
end
