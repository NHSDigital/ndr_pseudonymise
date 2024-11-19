require 'active_support/deprecation'
begin
  require 'active_support/deprecator'
rescue LoadError
  # Ignore error: 'active_support/deprecator' is not defined on active_support 7.0
end
require 'active_support'

require 'ndr_pseudonymise/version'
require 'ndr_pseudonymise/pseudonymisation_specification'

require 'ndr_pseudonymise/client'

require 'ndr_pseudonymise/demographics_only_pseudonymiser'
require 'ndr_pseudonymise/prescription_pseudonymiser'
require 'ndr_pseudonymise/progress_printer'
require 'ndr_pseudonymise/pseudonymisation_specification'
require 'ndr_pseudonymise/simple_pseudonymisation'

# Pseudonymise CSV data for matching purposes
module NdrPseudonymise
end
