# Fast, simple pseudonymisation of prescription data with a very controlled
# format.
# Only the first 2 fields are potentially identifiable: nhs number and date of
# birth.

require 'ndr_pseudonymise/simple_pseudonymisation'
require 'ndr_pseudonymise/pseudonymisation_specification'

require 'json'

module NdrPseudonymise
  # Pseudonymise prescription data
  class PrescriptionPseudonymiser < PseudonymisationSpecification
    PREAMBLE_V2_DEMOG_ONLY = 'Pseudonymised matching data v2.0-demog-only'.freeze

    def initialize(format_spec, key_bundle)
      super
      return if @format_spec[:demographics] == [0, 1]
      raise 'Invalid specification: expected nhsnumber and birthdate in first 2 columns'
    end

    # Validate a row of prescription data
    # Return false if this row is a valid data row, otherwise a list of errors
    def row_errors2(row)
      # Not significantly faster than optimised general #row_errors method
      (nhsnumber, birthdate) = row[0..1]
      unless nhsnumber.is_a?(String) && nhsnumber =~ /\A([0-9]{10})?\Z/
        raise 'Invalid NHS number'
      end
      raise 'Missing NHS number' if nhsnumber.size < 10
      unless birthdate.is_a?(String) && birthdate =~ /\A([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|)\Z/
        raise 'Invalid birthdate'
      end
    end

    # Pseudonymise a row of prescription data, returning an array of a single row:
    # [[packed_pseudoid_and_demographics, clinical_data1, ...]]
    # Where packed_pseudoid_and_demographics consists of
    # "pseudo_id1 (key_bundle) packed_pseudoid_and_demographics"
    def pseudonymise_row(row)
      @key_cache ||= {} # Cache pseudonymisation keys for more compact import
      all_demographics = { 'nhsnumber' => row[0], 'birthdate' => row[1] }
      key = all_demographics.to_json
      if @key_cache.key?(key)
        pseudo_id1, key_bundle, demog_key = @key_cache[key]
      else
        pseudo_id1, key_bundle, demog_key = NdrPseudonymise::SimplePseudonymisation.
                                            generate_keys_nhsnumber_demog_only(@salt1, @salt2, row[0])
        if !row[0].to_s.empty? && !row[1].to_s.empty? # && false to stop caching
          @key_cache = {} if @key_cache.size > 10000 # Limit cache size
          @key_cache[key] = [pseudo_id1, key_bundle, demog_key]
        end
      end
      encrypted_demographics = NdrPseudonymise::SimplePseudonymisation.
                               encrypt_data64(demog_key, all_demographics.to_json)
      packed_pseudoid_and_demographics = format('%s (%s) %s', pseudo_id1, key_bundle,
                                                encrypted_demographics)
      [[packed_pseudoid_and_demographics] + row[2..-1]]
    end

    # Header row for CSV data
    def csv_header_row
      [PREAMBLE_V2_DEMOG_ONLY]
    end

    # Append the output of pseudonymise_row to a CSV file
    def emit_csv_rows(out_csv, pseudonymised_row)
      out_csv << pseudonymised_row[0]
    end
  end
end
