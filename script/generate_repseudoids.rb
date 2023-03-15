#!/usr/bin/env ruby
require 'digest/sha2'

unless ARGV.size == 5
  puts <<~USAGE
    Usage: generate_repseudoids.rb NHSNUMBER BIRTHDATE POSTCODE SALT_ID SALT_REPSEUDO
      NHSNUMBER is a 10 digit NHS number (or a zero-length string)
      BIRTHDATE is in ISO format YYYY-MM-DD (or a zero-length string)
      POSTCODE is an upper case alphanumberic string (spaces will be removed and ignored)
      SALT_ID is a 32-character hex pseudonymisation key
      SALT_REPSEUDO is a 32-character hex repseudonymisation key

    Produces two 16-character hex values on a single line: repseudo_id1_short,repseudo_id2_short
      repseudo_id1_short is derived from NHSNUMBER, SALT_ID and SALT_REPSEUDO
      repseudo_id2_short is derived from BIRTHDATE, POSTCODE, SALT_ID and SALT_REPSEUDO

    If NHSNUMBER is a zero-length string, then repseudo_id1_short is not useful for linkage.
    If BIRTHDATE or POSTCODE is a zero-length string, then repseudo_id2_short is not useful.

    Example usage (using made-up demographics and salt values):
      $ generate_repseudoids.rb '1234567881' '1975-10-22' 'CB22 3AD' \\
          '1234567890abcdef1234567890abcdef' '0123456789abcdef1234567890abcdef'
      f82845dec2cd7379,051109c45665b97b
  USAGE
  abort
end

nhsnumber = ARGV[0]
birthdate = ARGV[1]
current_postcode = ARGV[2].delete(' ')
salt_id = ARGV[3]
salt_repseudo = ARGV[4]

# This code is stripped-down snippets from lib/ndr_pseudonymise/simple_pseudonymisation.rb
# and repseudonymisation logic from data_management_system/script/repseudo/ndr_repseudonymise.rb
unless nhsnumber.is_a?(String) && nhsnumber =~ /\A([0-9]{10})?\Z/
  raise 'Invalid NHS number'
end
unless current_postcode.is_a?(String) && current_postcode =~ /\A[A-Z0-9 ]*\Z/
  raise 'Invalid postcode'
end
unless birthdate.is_a?(String) && birthdate =~ /\A([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|)\Z/
  raise 'Invalid birthdate'
end

unless salt_id =~ /[0-9a-f]{32}/
  raise(ArgumentError,
        'Expected salt_id to contain at least 256 bits of hex characters (0-9, a-f)')
end
unless salt_repseudo =~ /[0-9a-f]{32}/
  raise(ArgumentError,
        'Expected salt_repseudo to contain at least 256 bits of hex characters (0-9, a-f)')
end

def data_hash(value, salt)
  Digest::SHA2.hexdigest(value.to_s + salt.to_s)
end

real_id1 = 'nhsnumber_' + nhsnumber
real_id2 = 'birthdate_postcode_' + birthdate + '_' + current_postcode.delete(' ')

pseudo_id1 = data_hash(real_id1, salt_id)
repseudo_id1 = data_hash("pseudoid_#{pseudo_id1}", salt_repseudo) # Re-pseudonymise
repseudo_id1_short = repseudo_id1[0..15]

pseudo_id2 = data_hash(real_id2, salt_id)
repseudo_id2 = data_hash("pseudoid_#{pseudo_id2}", salt_repseudo) # Re-pseudonymise
repseudo_id2_short = repseudo_id2[0..15]

puts repseudo_id1_short + ',' + repseudo_id2_short
