require 'test_helper'

module NdrPseudonymise
  class ClientTest < ActiveSupport::TestCase
    TestResponse = Struct.new(:code, :body)

    setup do
      @client = Client.new(host: 'test.host', token: 'wibble')
      @identifiers = { nhs_number: '0123456789“' }
    end

    test 'should be configurable with just host and token' do
      assert_kind_of Client, @client
    end

    test 'should be configurable context on intialisation' do
      client = Client.new(host: 'test.host', token: 'wibble', context: 'foo')
      assert_equal 'foo', client.context
    end

    test 'should be configurable context after the fact' do
      assert_nil @client.context

      context = { foo: 'bar' }
      @client.context = context

      assert_equal context, @client.context
    end

    test 'should be able to get keys' do
      @client.expects(:build_get_request).with('/keys')
      @client.stubs(request: TestResponse.new(200, '[{"a":"a"},{"a":"b"}]'))

      assert_equal [{ 'a' => 'a' }, { 'a' => 'b' }], @client.keys
    end

    test 'should be able to get variants' do
      @client.expects(:build_get_request).with('/variants')
      @client.stubs(request: TestResponse.new(200, '[{"a":"a"},{"a":"b"}]'))

      assert_equal [{ 'a' => 'a' }, { 'a' => 'b' }], @client.variants
    end

    test 'should raise when pseudonymising if no context given' do
      ex = assert_raises(ArgumentError) { @client.pseudonymise(identifiers: @identifiers) }
      assert_match(/context/, ex.message)
    end

    test 'should POST to the API host when pseudonymising' do
      response = TestResponse.new(200, '[{"a":"a"},{"a":"b"}]')

      @client.host.expects(request: response).with do |request|
        assert_kind_of Net::HTTP::Post, request
        assert_equal 'Token token="wibble"', request['Authorization']
        assert_match(/0123456789/, request.body)
        assert_equal 'application/json', request.content_type
      end

      @client.context = { custom: 'context' }
      data = @client.pseudonymise(identifiers: @identifiers)
      assert_equal [{ 'a' => 'a' }, { 'a' => 'b' }], data
    end

    test 'should raise helpful error when something goes wrong' do
      response = TestResponse.new(403, '{"errors": ["oh no", "no good"]}')

      @client.host.expects(request: response)

      exception = assert_raises(RuntimeError) do
        @client.pseudonymise(identifiers: @identifiers, context: 'foo')
      end
      assert_match(/An error occured/, exception.message)
      assert_match(/oh no.*no good/, exception.message)
    end

    test 'should raise unhelpful error when something unexpected goes wrong' do
      response = TestResponse.new(500, '')

      @client.host.expects(request: response)

      exception = assert_raises(RuntimeError) do
        @client.pseudonymise(identifiers: @identifiers, context: 'foo')
      end
      assert_match(/An error occured/, exception.message)
    end

    test 'should react naively to junk JSON data' do
      @client.host.expects(request: TestResponse.new(200, '{'))

      assert_raises(JSON::ParserError) do
        @client.pseudonymise(identifiers: @identifiers, context: 'foo')
      end
    end
  end
end
