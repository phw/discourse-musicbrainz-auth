# name: discourse-musicbrainz-auth
# about: OAuth2 Plugin for MusicBrainz strategy
# version: 0.3
# authors: Ohm Patel, Philipp Wolfer
# url: https://github.com/metabrainz/discourse-musicbrainz-auth

require_relative 'lib/omniauth/strategies/omniauth-musicbrainz.rb'


class Auth::MusicBrainzAuthenticator < Auth::ManagedAuthenticator
  def name
    "musicbrainz"
  end

  def enabled?
    SiteSetting.musicbrainz_enabled
  end

  def match_by_username
    # MusicBrainz user names are immutable
    true
  end

  def register_middleware(omniauth)
    omniauth.provider :musicbrainz,
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.musicbrainz_client_id
                        opts[:client_secret] = SiteSetting.musicbrainz_client_secret
                        opts[:client_options] = {
                          site: SiteSetting.musicbrainz_site_url,
                          authorize_url: SiteSetting.musicbrainz_authorize_url,
                          token_url: SiteSetting.musicbrainz_token_url
                        }
                        opts[:user_info_url] = SiteSetting.musicbrainz_user_info_url
                        if SiteSetting.musicbrainz_send_auth_header?
                          opts[:token_params] = {headers: {'Authorization' => basic_auth_header }}
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.musicbrainz_client_id}:#{SiteSetting.musicbrainz_client_secret}")
  end

  def primary_email_verified?(auth_token)
    SiteSetting.musicbrainz_email_verified? &&
      !auth_token.dig(:info, :email).nil? &&
      auth_token.dig(:info, :email_verified)
  end
end

auth_provider title_setting: "musicbrainz_button_title",
              authenticator: Auth::MusicBrainzAuthenticator.new

register_css <<CSS

  button.btn-social.musicbrainz {
    background-color: #8A2BE2 !important;
  }

CSS
