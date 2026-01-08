package gr.gunet.broker.gsis;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderModel;

import static org.junit.jupiter.api.Assertions.*;

class GsisIdentityProviderConfigTest {

    private GsisIdentityProviderConfig config;
    private IdentityProviderModel model;

    @BeforeEach
    void setUp() {
        model = new IdentityProviderModel();
        model.setProviderId(GsisIdentityProviderConfig.PROVIDER_ID);
        config = new GsisIdentityProviderConfig(model);
    }

    @Test
    void testProviderIdConstant() {
        assertEquals("gsis-taxis", GsisIdentityProviderConfig.PROVIDER_ID);
    }

    @Test
    void testSetAndGetAuthorizationUrl() {
        String authUrl = "https://example.com/authorize";
        config.setAuthorizationUrl(authUrl);
        assertEquals(authUrl, config.getAuthorizationUrl());
    }

    @Test
    void testSetAndGetTokenUrl() {
        String tokenUrl = "https://example.com/token";
        config.setTokenUrl(tokenUrl);
        assertEquals(tokenUrl, config.getTokenUrl());
    }

    @Test
    void testSetAndGetUserInfoUrl() {
        String userInfoUrl = "https://example.com/userinfo";
        config.setUserInfoUrl(userInfoUrl);
        assertEquals(userInfoUrl, config.getUserInfoUrl());
    }

    @Test
    void testSetAndGetLogoutUrl() {
        String logoutUrl = "https://example.com/logout";
        config.setLogoutUrl(logoutUrl);
        assertEquals(logoutUrl, config.getLogoutUrl());
    }

    @Test
    void testGetNullUrlsReturnsNull() {
        assertNull(config.getAuthorizationUrl());
        assertNull(config.getTokenUrl());
        assertNull(config.getUserInfoUrl());
        assertNull(config.getLogoutUrl());
    }

    @Test
    void testCopyConstructor() {
        String authUrl = "https://example.com/authorize";
        String tokenUrl = "https://example.com/token";

        config.setAuthorizationUrl(authUrl);
        config.setTokenUrl(tokenUrl);

        GsisIdentityProviderConfig copiedConfig = new GsisIdentityProviderConfig(config);
        assertEquals(authUrl, copiedConfig.getAuthorizationUrl());
        assertEquals(tokenUrl, copiedConfig.getTokenUrl());
    }
}
