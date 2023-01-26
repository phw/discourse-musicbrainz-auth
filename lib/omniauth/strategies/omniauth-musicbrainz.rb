require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Musicbrainz < ::OmniAuth::Strategies::OAuth2
      option :name, :musicbrainz

      option :scope, "profile email"

      option :client_options, {
        :site          => 'https://musicbrainz.org',
        :authorize_url => '/oauth2/authorize',
        :token_url     => '/oauth2/token'
      }

      option :provider_ignores_state, true

      option :user_info_url, '/oauth2/userinfo'

      uid{ raw_info['metabrainz_user_id'] }

      info do
        {
          :nickname => raw_info['sub'],
          :name => raw_info['sub'],
          :email => raw_info['email'],
          :email_verified => raw_info['email_verified'],
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get(options.user_info_url).parsed
      end

      def callback_url
        # Workaround for https://github.com/omniauth/omniauth-oauth2/issues/93
        full_host + script_name + callback_path
      end
    end
  end
end
