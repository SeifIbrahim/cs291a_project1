# frozen_string_literal: true

require 'active_support/hash_with_indifferent_access'
require 'json'
require 'jwt'
require 'pp'

# source: https://stackoverflow.com/questions/21715364/rails-case-insensitive-params-hash-keys?noredirect=1&lq=1
class CaseInsensitiveHash < HashWithIndifferentAccess
  def [](key)
    super convert_key(key)
  end

  protected

  def convert_key(key)
    key.respond_to?(:downcase) ? key.downcase : key
  end
end

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  ci_event = CaseInsensitiveHash.new(event)
  if ci_event['path'] == '/token'
    # Handle errors
    return response(status: 415) if ci_event['type'] != 'aplication/json'
    begin
      body = JSON.parse(ci_event['body'])
    rescue JSON::ParserError
      return response(status: 422)
    end
    # Generate a token
    payload = {
      data: body,
      exp: Time.now.to_i + 5,
      nbf: Time.now.to_i + 2
    }
    token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
    response(body: { 'token' => token }, status: 200)
  elsif ci_event['path'] == '/'
    auth_tokens = ci_event['Authorization'].split
    return response(status: 403) if auth_tokens[0] != 'Bearer'
    begin
      token = JWT.decode(payload, ENV['JWT_SECRET'])
    rescue JWT::DecodeError
      return response(status: 401)
    end
    response(token[:data], status: 200)
  else
    response(status: 404)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
