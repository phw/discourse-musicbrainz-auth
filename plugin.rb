# name: discourse-musicbrainz-auth
# about: OAuth2 Plugin for MusicBrainz strategy
# version: 0.2
# authors: Ohm Patel, Philipp Wolfer
# url: https://github.com/metabrainz/discourse-musicbrainz-auth

class Auth::Oauth2BasicAuthenticator < Auth::ManagedAuthenticator
  class Oauth2BasicStrategy < ::OmniAuth::Strategies::OAuth2
    # Give your strategy a name.
    option :name, :oauth2

    # These are called after authentication has succeeded. If
    # possible, you should try to set the UID without making
    # additional calls (if the user id is returned with the token
    # or as a URI parameter). This may not be possible with all
    # providers.
    uid{ raw_info[SiteSetting.oauth2_json_user_id_path] }

    def info
      user_info = {}
      json_walk(user_info, raw_info, :user_id)
      json_walk(user_info, raw_info, :nickname)
      json_walk(user_info, raw_info, :name)
      json_walk(user_info, raw_info, :email)
      user_info
    end

    extra do
      {
        'raw_info' => raw_info
      }
    end

    def raw_info
      opts = {
        :headers => {
          'Authorization' => "Bearer #{access_token.token}"
        }
      }
      @raw_info ||= access_token.get(options.user_info_url, opts).parsed
    end

    def walk_path(fragment, segments)
      first_seg = segments[0]
      return if first_seg.blank? || fragment.blank?
      return nil unless fragment.is_a?(Hash)
      deref = fragment[first_seg] || fragment[first_seg.to_sym]

      return (deref.blank? || segments.size == 1) ? deref : walk_path(deref, segments[1..-1])
    end

    def json_walk(result, user_json, prop)
      path = SiteSetting.send("oauth2_json_#{prop}_path")
      if path.present?
        segments = path.split('.')
        val = walk_path(user_json, segments)
        result[prop] = val if val.present?
      end
    end

    def callback_url
      # Workaround for https://github.com/omniauth/omniauth-oauth2/issues/93
      full_host + script_name + callback_path
    end
  end

  def name
    "oauth2_basic"
  end

  def enabled?
    SiteSetting.oauth2_enabled
  end

  def match_by_username
    # MusicBrainz user names are immutable
    true
  end

  def register_middleware(omniauth)
    omniauth.provider Oauth2BasicStrategy,
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.oauth2_client_id
                        opts[:client_secret] = SiteSetting.oauth2_client_secret
                        opts[:provider_ignores_state] = true
                        opts[:client_options] = {
                          authorize_url: SiteSetting.oauth2_authorize_url,
                          token_url: SiteSetting.oauth2_token_url
                        }
                        opts[:user_info_url] = SiteSetting.oauth2_user_json_url
                        if SiteSetting.oauth2_send_auth_header?
                          opts[:token_params] = {headers: {'Authorization' => basic_auth_header }}
                        end
                        opts[:scope] = "profile email"
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def primary_email_verified?(auth_token)
    SiteSetting.oauth2_email_verified? &&
      !auth_token.dig(:info, :email).nil? &&
      auth_token.dig(:info, :email_verified)
  end
end

auth_provider title_setting: "oauth2_button_title",
              authenticator: Auth::Oauth2BasicAuthenticator.new

register_css <<CSS

  button.btn-social.musicbrainz {
    background-color: #8A2BE2 !important;
  }

CSS
