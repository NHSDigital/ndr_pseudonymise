require 'json'
require 'net/http'

module NdrPseudonymise
  # A class to wrap interactions with a remote pseudonymisation service.
  #
  # Sample usage, against a local pseudonymisation service:
  #
  #   client = NdrPseudonymise::Client.new(
  #     host: 'localhost', port: 3000, use_ssl: false,
  #     token: 'your_name:some_token', context: 'just testing'
  #   )
  #
  #   client.pseudonymise(identifiers: { nhs_number: '0123456789' })
  #
  class Client
    attr_accessor :context, :host

    def initialize(host:, token:, port: 443, use_ssl: true, root_path: '/api/v1', context: nil)
      @host = Net::HTTP.new(host, port).tap { |http| http.use_ssl = use_ssl }
      @header = "Token token=#{token.inspect}"
      @root_path = root_path
      @context = context
    end

    # Returns a list of pseudonymisation keys that the current user is able to use.
    #
    # Sample usage:
    #
    #   client.keys #=> [{name"=>"key one", "supported_variants"=>[1]}, ...]
    #
    def keys
      get('/keys')
    end

    # Returns a list of variants that the current user is able to use.
    #
    # Sample usage:
    #
    #   client.variants #=> [{"variant"=>"1", "required_identifiers" => ["nhs_number"]}, ...]
    #
    def variants
      get('/variants')
    end

    # Returns pseudonymised identifiers for the supplied identifiers.
    # By default, the pseudonymisation service requests all ID variants
    # from all available keys; this can be filtered by using `variants`
    # and `key_names` respectively.
    #
    # Sample usage:
    #
    #   client.pseudonymise(identifiers: { nhs_number: '0123456789' }) #=>
    #     [
    #       { "key_name"=>"key one", "variant"=>1, "pseudoid"=>"b549ef342...", "identifiers"=>... },
    #       { "key_name"=>"key two", "variant"=>1, "pseudoid"=>"0ebd91c13...", "identifiers"=>... },
    #     ]
    #
    #   client.pseudonymise(identifiers: { postcode: 'CB22 3AD', birth_date: '2000-01-01' }, key_names: ['key two']) #=>
    #     [
    #       { "key_name"=>"key two", "variant"=>2, "pseudoid"=>"043d5fc1a...", "identifiers"=>... },
    #     ]
    #
    def pseudonymise(identifiers:, key_names: [], variants: [], context: @context)
      raise ArgumentError, 'you must supply context!' if context.blank?

      data = { identifiers: identifiers, context: context }
      data[:key_names] = key_names if key_names.present?
      data[:variants] = variants if variants.present?

      post('/pseudonymise', data)
    end

    private

    def get(endpoint)
      handle_response { request(build_get_request(endpoint)) }
    end

    def post(endpoint, params)
      handle_response { request(build_post_request(endpoint, params)) }
    end

    delegate :request, to: :@host

    def handle_response
      response = yield
      data = response.body.present? ? JSON.parse(response.body) : {}

      case response.code.to_i
      when 200
        data
      else
        raise <<~MESSAGE
          An error occured trying to use the pseudonymisation service. Details:
          #{data.fetch('errors', []).join(', ')}
        MESSAGE
      end
    end

    def build_get_request(endpoint)
      Net::HTTP::Get.new(@root_path + endpoint).tap do |request|
        request['Authorization'] = @header
      end
    end

    def build_post_request(endpoint, params)
      Net::HTTP::Post.new(@root_path + endpoint).tap do |request|
        request['Authorization'] = @header
        request['Content-Type'] = 'application/json'
        request.body = JSON.dump(params)
      end
    end
  end
end
