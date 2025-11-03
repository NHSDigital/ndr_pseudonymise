## [Unreleased]
## Fixed
* Tests should support Rails 7.0, 7.1, 7.2, 8.0, Ruby 3.4
* Remove hidden Rails gemfile dependency

## Added
* Added minimalist script to generate repseudoids

## 0.4.2 / 2022-10-25
## Changed
* ndr_encrypt add recursively includes directory contents

## 0.4.1 / 2022-10-18
## Added
# Add ndr_encrypt utility script for image encryption.

## 0.4.0 / 2020-07-08
## Changed
* Update client to reflect API updates

## 0.3.0 / 2020-07-08
## Added
* Added pseudonymisation service client

## 0.2.11 / 2019-03-15
## Added
* SimplePseudonymisation should include decryption methods.

# 0.2.10 / 2019-03-06
## Fixed
* Pseudonymisation: allow blank dates of birth.

# 0.2.9 / 2018-12-10
## Changed
* # Include row numbers in CSV pseudonymisation errors.

# 0.2.8 / 2018-12-07
## Fixed
* Allow null NHS numbers for DemographicsOnlyPseudonymiser

# 0.2.7 / Unreleased

# 0.2.6 / 2018-08-30
## Fixed
* Remove unnecessary pry runtime dependency

# 0.2.5 / 2018-07-24
## Added
* Support pseudonymising data with multiple demographics columns, and various date formats

# 0.2.4 / 2018-07-24
## Added
* Add helper methods for reformatting pseudonymised data into ordinary CSV columns.
