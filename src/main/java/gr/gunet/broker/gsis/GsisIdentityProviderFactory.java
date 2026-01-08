package gr.gunet.broker.gsis;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class GsisIdentityProviderFactory
        extends AbstractIdentityProviderFactory<GsisIdentityProvider> {

    public static final String PROVIDER_ID = GsisIdentityProviderConfig.PROVIDER_ID;
    public static final String DEFAULT_AUTH_URL = "https://oauth2.gsis.gr/oauth2server/oauth/authorize";
    public static final String DEFAULT_TOKEN_URL = "https://oauth2.gsis.gr/oauth2server/oauth/token";
    public static final String DEFAULT_SCOPE = "";
    public static final String DEFAULT_USER_INFO_URL = "https://oauth2.gsis.gr/oauth2server/userinfo?format=xml";
    public static final String DEFAULT_LOGOUT_URL = "https://oauth2.gsis.gr/oauth2server/logout/{clientId}/";
    public static final String DEFAULT_GENERATE_PLACEHOLDER_EMAIL = "true";
    public static final String DEFAULT_GENERATE_SCOPED_USERNAME = "true";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty authUrl = new ProviderConfigProperty();
        authUrl.setName(GsisIdentityProviderConfig.AUTHORIZATION_URL);
        authUrl.setLabel("Authorization URL");
        authUrl.setType(ProviderConfigProperty.STRING_TYPE);
        authUrl.setHelpText("The OAuth2 authorization URL for the external Identity Provider.");
        authUrl.setDefaultValue(DEFAULT_AUTH_URL);
        authUrl.setRequired(true);
        CONFIG_PROPERTIES.add(authUrl);

        ProviderConfigProperty tokenUrl = new ProviderConfigProperty();
        tokenUrl.setName(GsisIdentityProviderConfig.TOKEN_URL);
        tokenUrl.setLabel("Token URL");
        tokenUrl.setType(ProviderConfigProperty.STRING_TYPE);
        tokenUrl.setHelpText("The OAuth2 token URL for the external Identity Provider.");
        tokenUrl.setDefaultValue(DEFAULT_TOKEN_URL);
        tokenUrl.setRequired(true);
        CONFIG_PROPERTIES.add(tokenUrl);

        ProviderConfigProperty userInfoUrl = new ProviderConfigProperty();
        userInfoUrl.setName(GsisIdentityProviderConfig.USER_INFO_URL);
        userInfoUrl.setLabel("User Info URL");
        userInfoUrl.setType(ProviderConfigProperty.STRING_TYPE);
        userInfoUrl.setHelpText("The URL to fetch the user profile from the external Identity Provider.");
        userInfoUrl.setDefaultValue(DEFAULT_USER_INFO_URL);
        userInfoUrl.setRequired(true);
        CONFIG_PROPERTIES.add(userInfoUrl);

        ProviderConfigProperty logoutUrl = new ProviderConfigProperty();
        logoutUrl.setName(GsisIdentityProviderConfig.LOGOUT_URL);
        logoutUrl.setLabel("Logout URL");
        logoutUrl.setType(ProviderConfigProperty.STRING_TYPE);
        logoutUrl.setHelpText(
                "The URL for logging out from the external Identity Provider. The {clientId} placeholder will be replaced with the actual client ID.");
        logoutUrl.setDefaultValue(DEFAULT_LOGOUT_URL);
        logoutUrl.setRequired(true);
        CONFIG_PROPERTIES.add(logoutUrl);

        ProviderConfigProperty generatePlaceholderEmail = new ProviderConfigProperty();
        generatePlaceholderEmail.setName(GsisIdentityProviderConfig.GENERATE_PLACEHOLDER_EMAIL);
        generatePlaceholderEmail.setLabel("Auto-generate Email from template");
        generatePlaceholderEmail.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        generatePlaceholderEmail.setHelpText(
                "When enabled and the email field is marked as required in the realm settings, "
                + "this populates the email attribute with a placeholder value following the username@gsis template. "
                + "Note: This generates a placeholder string, not a functional email address.");
        generatePlaceholderEmail.setDefaultValue(DEFAULT_GENERATE_PLACEHOLDER_EMAIL);
        generatePlaceholderEmail.setRequired(true);
        CONFIG_PROPERTIES.add(generatePlaceholderEmail);

        ProviderConfigProperty generateScopedUsername = new ProviderConfigProperty();
        generateScopedUsername.setName(GsisIdentityProviderConfig.GENERATE_SCOPED_USERNAME);
        generateScopedUsername.setLabel("Generate Scoped Username");
        generateScopedUsername.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        generateScopedUsername.setHelpText("When enabled, this will generate usernames scoped to the Identity Provider to avoid conflicts with existing usernames in Keycloak.");
        generateScopedUsername.setDefaultValue(DEFAULT_GENERATE_SCOPED_USERNAME);
        generateScopedUsername.setRequired(true);
        CONFIG_PROPERTIES.add(generateScopedUsername);
    }

    @Override
    public String getName() {
        return "GsisTaxis";
    }

    @Override
    public GsisIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new GsisIdentityProvider(session, new GsisIdentityProviderConfig(model));
    }

    @Override
    public GsisIdentityProviderConfig createConfig() {
        return new GsisIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
