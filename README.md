## NdrPseudonymise [![Build Status](https://github.com/publichealthengland/ndr_pseudonymise/workflows/Test/badge.svg)](https://github.com/publichealthengland/ndr_pseudonymise/actions?query=workflow%3Atest)

Pseudonymise confidential data, in CSV format, with specifications for which fields to be encrypted.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ndr_pseudonymise'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ndr_pseudonymise

## Usage

Example input file:
nhsnumber,birthdate,postcode,surname,data1,date2
1234567881,1955-01-01,CB22 3AD,SMITH,xyz,abc
,01/02/1955,,JONES,zzz,aaa

outfile.yml:

File version:
'something-1'

Pseudonymised keys:
[sha1('nhsnumber_1234567881' + salt1), 'n-random-uuencoded-bits-1']
[sha1('birthdate_postcode_1955-01-01_CB22 3AD' + salt1), 'n-random-uuencoded-bits-2']
[sha1('birthdate_postcode_1955-02-01_' + salt1), 'n-random-uuencoded-bits-3']

Encrypted demographics
[sha1('nhsnumber_1234567881' + salt1), encrypt(['surname' => 'SMITH'], 'nhsnumber_1234567881' + 'n-random-uuencoded-bits-1' + salt2, 'n-random-uuencoded-bits2-1']
[sha1('birthdate_postcode_1955-01-01_CB22 3AD'  + salt1), encrypt(['surname' => 'SMITH'], 'birthdate_postcode_1955-01-01_CB22 3AD'  + 'n-random-uuencoded-bits-2' + salt2, 'n-random-uuencoded-bits2-2']
[sha1('birthdate_postcode_1955-02-01_' + salt1), encrypt(['surname' => 'JONES'], 'birthdate_postcode_1955-02-01_'  + 'n-random-uuencoded-bits-2' + salt2, 'n-random-uuencoded-bits2-3']

Encrypted data
[sha1('nhsnumber_1234567881' + salt1), encrypt(['xyz','abc'], 1', 'nhsnumber_1234567881' + 'n-random-uuencoded-bits2-1' + salt2)]
[sha1('birthdate_postcode_1955-01-01_CB22 3AD' + salt1), encrypt(['xyz','abc'], 1', 'birthdate_postcode_1955-01-01_CB22 3AD' + 'n-random-uuencoded-bits2-2' + salt2)]
[sha1('birthdate_postcode_1955-02-01_' + salt1), encrypt(['zzz','aaa'], 1', 'birthdate_postcode_1955-02-01_' + 'n-random-uuencoded-bits2-3' + salt2)]

Encrypted meta-data, header row?

TODO: Replace text e.g. 'nhsnumber_1234567881' on RHS above with e.g. sha1('extraprefix_' + 'nhsnumber_1234567881') i.e. something non-disclosive, derivable from the original data.
TODO: Put original versions of e.g. nhsnumber, birthdate, postcode into "Encrypted demographics"
TODO: Maybe salt2 could be retained, to allow some fuzzy demographic matching, without the possibility of brute forcing the main identifiers??? Or maybe you can do pseudonymised matching without any salt...

Open questions:
Standard date / postcode normalisation
Do you escape underscores in field values
Do we need salt2, or re-use salt1?
Can we remove n-random-uuencoded-bits2 into the pseudonymised keys hash?

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).
