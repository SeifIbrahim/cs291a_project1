# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  headers = event['headers'].transform_keys(&:downcase)
  if event['path'] == '/token'
    # Handle errors
    return response(status: 405) unless event['httpMethod'] == 'POST'
    return response(status: 415) if headers['content-type'] != 'application/json'
    begin
      unparsed_body = event.fetch('body')
      return response(status: 422) if unparsed_body.nil?
      body = JSON.parse(unparsed_body)
    rescue JSON::ParserError, KeyError
      return response(status: 422)
    end
    # Generate a token
    payload = {
      data: body,
      exp: Time.now.to_i + 5,
      nbf: Time.now.to_i + 2
    }
    token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
    response(body: { 'token' => token }, status: 201)
  elsif event['path'] == '/'
    # Handle errors
    return response(status: 405) unless event['httpMethod'] == 'GET'
    return response(status: 403) unless headers.key?('authorization')
    auth_tokens = headers['authorization'].split
    return response(status: 403) unless auth_tokens[0] == 'Bearer'
    begin
      token = JWT.decode(auth_tokens[1], ENV['JWT_SECRET'])
    rescue JWT::ImmatureSignature, JWT::ExpiredSignature
      return response(status: 401)
    rescue JWT::DecodeError
      return response(status: 403)
    end
    response(body: token[0]['data'], status: 200)
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
               'body' => nil,
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 5,
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
