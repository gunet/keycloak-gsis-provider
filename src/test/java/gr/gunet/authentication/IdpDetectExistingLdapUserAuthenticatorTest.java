package gr.gunet.authentication;

import gr.gunet.utils.ExternalAttributeExtractor;
import gr.gunet.utils.LDAPSearchUtils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.mockito.MockedStatic;

import org.keycloak.common.Profile;

import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Set;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IdpDetectExistingLdapUserAuthenticatorTest {

    private IdpDetectExistingLdapUserAuthenticator authenticator;

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private UserProvider userProvider;

    @Mock
    private AuthenticatorConfigModel authConfig;

    @Mock
    private SerializedBrokeredIdentityContext serializedCtx;

    @Mock
    private BrokeredIdentityContext brokerContext;

    @Mock
    private AuthenticationSessionModel authSession;

    @Mock
    LoginFormsProvider loginFormsProvider;

    @Mock
    private EventBuilder event;

    @Mock
    private Response mockResponse;

    // Mocked static Profile
    private MockedStatic<Profile> profileStatic;
    private Profile profileMock;

    @BeforeEach
    void setup() {
        authenticator = new IdpDetectExistingLdapUserAuthenticator();

        when(context.getRealm()).thenReturn(realm);
        when(context.getSession()).thenReturn(session);
        when(session.users()).thenReturn(userProvider);
        when(session.getProvider(LoginFormsProvider.class)).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setAuthenticationSession(any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(anyString(), (Object[]) any(Object[].class)))
                .thenReturn(loginFormsProvider);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getEvent()).thenReturn(event);
        when(event.detail(anyString(), anyString())).thenReturn(event);
        doNothing().when(event).error(anyString());
        when(context.getAuthenticatorConfig()).thenReturn(authConfig);
        when(authConfig.getConfig()).thenReturn(new HashMap<>());
        when(brokerContext.getIdpConfig()).thenReturn(new IdentityProviderModel());
        when(loginFormsProvider.createErrorPage(any())).thenReturn(mockResponse);

        profileMock = mock(Profile.class);
        profileStatic = mockStatic(Profile.class);
        profileStatic.when(Profile::getInstance).thenReturn(profileMock);
        profileStatic.when(() -> Profile.isFeatureEnabled(any(Profile.Feature.class))).thenReturn(false);
    }

    @AfterEach
    void teardown() {
        if (profileStatic != null) {
            profileStatic.close();
        }
    }

    /**
     * Helper to setup config values.
     */
    private void setConfig(String externalAttr, String ldapAttr) {
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_ATTR, externalAttr);
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_ATTR, ldapAttr);
    }

    @Test
    void testMissingConfiguration() {
        when(authConfig.getConfig()).thenReturn(null);

        authenticator.authenticateImpl(context, serializedCtx, brokerContext);

        verify(context, description("Expected to fail authentication"))
                .failure(eq(AuthenticationFlowError.IDENTITY_PROVIDER_DISABLED));
    }

    @Test
    void testExternalAttributeNotFound() {
        setConfig("taxid", "tin");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "true");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "false");

        // ExternalAttributeExtractor returns empty => simulate
        mockStatic(ExternalAttributeExtractor.class).close();

        try (var mocked = mockStatic(ExternalAttributeExtractor.class)) {
            mocked.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>());

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to fail authentication")).failure(
                    eq(AuthenticationFlowError.UNKNOWN_USER),
                    any(Response.class));
        }
    }

    @Test
    void testNoLdapUsersFound() {

        setConfig("taxid", "tin");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "true");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "false");

        try (var mocked = mockStatic(ExternalAttributeExtractor.class)) {
            mocked.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.empty());

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to fail authentication")).failure(
                    eq(AuthenticationFlowError.UNKNOWN_USER),
                    any(Response.class));
        }
    }

    @Test
    void testMultipleUsersFound_NoValidation() {
        setConfig("taxid", "tin");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "false");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "true");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LEVENSHTEIN_THRESHOLD,
                "0");

        UserModel user = mock(UserModel.class);
        UserModel user2 = mock(UserModel.class);
        when(user.getAttributeStream("lastname")).thenReturn(Stream.of("ΣΩΣΤΟ_ΕΠΙΘΕΤΟ"));
        when(user.getAttributeStream("lastname")).thenReturn(Stream.of("ΛΑΘΟΣ_ΕΠΙΘΕΤΟ"));

        try (var ext = mockStatic(ExternalAttributeExtractor.class)) {

            ext.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            ext.when(() -> ExternalAttributeExtractor.extractValues("lastname", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("ΛΑΘΟΣ_ΕΠΙΘΕΤΟ")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(user, user2));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to fail authentication")).failure(
                    eq(AuthenticationFlowError.USER_CONFLICT),
                    any(Response.class));
        }
    }

    @Test
    void testMultipleUsersFound_FailedValidation() {
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "true");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "false");

        setConfig("taxid", "tin");

        UserModel u1 = mock(UserModel.class);
        UserModel u2 = mock(UserModel.class);

        try (var mocked = mockStatic(ExternalAttributeExtractor.class)) {
            mocked.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(u1, u2));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to fail authentication")).failure(
                    eq(AuthenticationFlowError.USER_CONFLICT),
                    any(Response.class));
        }
    }

    @Test
    void testSingleUserFound_Success() {
        setConfig("taxid", "tin");

        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn("USER123");

        try (var mocked = mockStatic(ExternalAttributeExtractor.class)) {

            mocked.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(user));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to execute setUser")).setUser(user);
            verify(context, description("Expected to make context success")).success();
        }
    }

    @Test
    void testValidationSuccess_LevenshteinThreshold1() {
        setConfig("taxid", "tin");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "true");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "false");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LEVENSHTEIN_THRESHOLD,
                "1");

        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn("U123");
        when(user.getAttributeStream("lastname")).thenReturn(Stream.of("ΣΩΣΤΟ_ΕΠΙΘΕΤΟ"));

        try (var extMock = mockStatic(ExternalAttributeExtractor.class);
                var valMock = mockStatic(LDAPSearchUtils.class)) {

            extMock.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            extMock.when(() -> ExternalAttributeExtractor.extractValues("lastname", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("ΣΩΣΤΟ_ΕΠΙΘΕΤ")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(user));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to execute setUser")).setUser(user);
            verify(context, description("Expected to make context success")).success();
        }
    }

    @Test
    void testValidationFails_LevenshteinThreshold0() {
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "true");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "false");

        setConfig("taxid", "tin");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LEVENSHTEIN_THRESHOLD,
                "0");

        UserModel user = mock(UserModel.class);
        when(user.getAttributeStream("lastname")).thenReturn(Stream.of("ΣΩΣΤΟ_ΕΠΙΘΕΤΟ"));

        try (var ext = mockStatic(ExternalAttributeExtractor.class)) {

            ext.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            ext.when(() -> ExternalAttributeExtractor.extractValues("lastname", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("ΣΩΣΤΟ_ΕΠΙΘΕΤ")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(user));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to fail authentication"))
                    .failure(eq(AuthenticationFlowError.UNKNOWN_USER), any(Response.class));
        }
    }

    @Test
    void testValidationFails_NoLastname() {
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "true");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "false");

        setConfig("taxid", "tin");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LEVENSHTEIN_THRESHOLD,
                "0");

        UserModel user = mock(UserModel.class);
        when(user.getAttributeStream("lastname")).thenReturn(Stream.of());

        try (var ext = mockStatic(ExternalAttributeExtractor.class)) {

            ext.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            ext.when(() -> ExternalAttributeExtractor.extractValues("lastname", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("ΛΑΘΟΣ_ΕΠΙΘΕΤΟ")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(user));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to fail authentication"))
                    .failure(eq(AuthenticationFlowError.UNKNOWN_USER), any(Response.class));
        }
    }

    @Test
    void testValidationSuccess_NoValidation() {

        setConfig("taxid", "tin");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "false");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "true");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LEVENSHTEIN_THRESHOLD,
                "0");

        UserModel user = mock(UserModel.class);
        when(user.getAttributeStream("lastname")).thenReturn(Stream.of("ΣΩΣΤΟ_ΕΠΙΘΕΤΟ"));

        try (var ext = mockStatic(ExternalAttributeExtractor.class)) {

            ext.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            ext.when(() -> ExternalAttributeExtractor.extractValues("lastname", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("ΛΑΘΟΣ_ΕΠΙΘΕΤΟ")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(user));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to execute setUser")).setUser(user);
            verify(context, description("Expected to make context success")).success();
        }
    }

    @Test
    void testValidationSuccess_NullLDAP() {

        setConfig("taxid", "tin");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS, "true");
        authConfig.getConfig().put(IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE, "true");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_VALIDATE_ATTR,
                "lastname");
        authConfig.getConfig().put(
                IdpDetectExistingLdapUserAuthenticatorFactory.LEVENSHTEIN_THRESHOLD,
                "0");

        UserModel user = mock(UserModel.class);
        when(user.getAttributeStream("lastname")).thenReturn(Stream.of());

        try (var ext = mockStatic(ExternalAttributeExtractor.class)) {

            ext.when(() -> ExternalAttributeExtractor.extractValues("taxid", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("011111111")));

            ext.when(() -> ExternalAttributeExtractor.extractValues("lastname", brokerContext))
                    .thenReturn(new java.util.HashSet<>(Set.of("ΛΑΘΟΣ_ΕΠΙΘΕΤΟ")));

            when(userProvider.searchForUserByUserAttributeStream(realm, "tin", "011111111"))
                    .thenReturn(Stream.of(user));

            authenticator.authenticateImpl(context, serializedCtx, brokerContext);

            verify(context, description("Expected to execute setUser")).setUser(user);
            verify(context, description("Expected to make context success")).success();
        }
    }
}
