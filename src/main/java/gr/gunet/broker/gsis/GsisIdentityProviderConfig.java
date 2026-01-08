package gr.gunet.broker.gsis;

import static org.keycloak.common.util.UriUtils.checkUrl;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;

public class GsisIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public static final String PROVIDER_ID = "gsis-taxis";

    public static final String AUTHORIZATION_URL = "authorizationUrl";
    public static final String TOKEN_URL = OAuth2IdentityProviderConfig.TOKEN_ENDPOINT_URL;
    public static final String USER_INFO_URL = "userInfoUrl";
    public static final String LOGOUT_URL = "logoutUrl";
    public static final String GENERATE_PLACEHOLDER_EMAIL = "generatePlaceholderEmail";
    public static final String GENERATE_SCOPED_USERNAME = "generateScopedUsername";

    public GsisIdentityProviderConfig() {
        super();
    }

    public GsisIdentityProviderConfig(GsisIdentityProviderConfig other) {
        super(other);
    }

    public GsisIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public GsisIdentityProviderConfig(OAuth2IdentityProviderConfig other) {
        super(other);
    }

    @Override
    public String getAuthorizationUrl() {
        return getConfig().get(AUTHORIZATION_URL);
    }

    @Override
    public void setAuthorizationUrl(String authorizationUrl) {
        getConfig().put(AUTHORIZATION_URL, authorizationUrl);
    }

    @Override
    public String getTokenUrl() {
        return getConfig().get(TOKEN_URL);
    }

    @Override
    public void setTokenUrl(String tokenUrl) {
        getConfig().put(TOKEN_URL, tokenUrl);
    }

    @Override
    public String getUserInfoUrl() {
        return getConfig().get(USER_INFO_URL);
    }

    @Override
    public void setUserInfoUrl(String userInfoUrl) {
        getConfig().put(USER_INFO_URL, userInfoUrl);
    }

    public String getLogoutUrl() {
        return getConfig().get(LOGOUT_URL);
    }

    public void setLogoutUrl(String logoutUrl) {
        getConfig().put(LOGOUT_URL, logoutUrl);
    }

    public boolean isGeneratePlaceholderEmail() {
        return Boolean.parseBoolean(getConfig().get(GENERATE_PLACEHOLDER_EMAIL));
    }

    public void setGeneratePlaceholderEmail(boolean generatePlaceholderEmail) {
        getConfig().put(GENERATE_PLACEHOLDER_EMAIL, String.valueOf(generatePlaceholderEmail));
    }

    public boolean isGenerateScopedUsernameEnabled() {
        return Boolean.parseBoolean(getConfig().get(GENERATE_SCOPED_USERNAME));
    }

    public void setGenerateScopedUsername(boolean generateScopedUsername) {
        getConfig().put(GENERATE_SCOPED_USERNAME, String.valueOf(generateScopedUsername));
    }

    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);
        SslRequired sslRequired = realm.getSslRequired();

        checkUrl(sslRequired, getLogoutUrl(), LOGOUT_URL);
    }
}
