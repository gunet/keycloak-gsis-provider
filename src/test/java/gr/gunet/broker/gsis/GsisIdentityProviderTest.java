package gr.gunet.broker.gsis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import gr.gunet.TestProfile;
import gr.gunet.utils.ExternalAttributeExtractor;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPAttributeRequired;
import java.util.Map;
import java.util.Set;

import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.forms.login.LoginFormsProvider;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit and Functional tests for GsisIdentityProvider that mock HTTP calls to
 * the external provider.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GsisIdentityProviderTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private GsisIdentityProviderConfig config;

    @Mock
    private UserProfileProvider userProfileProvider;

    private GsisIdentityProvider provider;

    @BeforeEach
    void setUp() {
        setupUserProfileProvider();
        provider = new GsisIdentityProvider(session, config);
    }

    /**
     * Setup mock UserProfileProvider with required configuration
     */
    private void setupUserProfileProvider() {
        when(session.getProvider(UserProfileProvider.class)).thenReturn(userProfileProvider);
        setupMockConfig(false);
    }

    /**
     * Setup configuration mock with specified isAlways value
     */
    private void setupMockConfig(boolean isAlwaysValue) {
        // Create mock objects with proper types
        UPAttributeRequired required = mock(UPAttributeRequired.class);
        when(required.isAlways()).thenReturn(isAlwaysValue);
        
        UPAttribute attribute = mock(UPAttribute.class);
        when(attribute.getRequired()).thenReturn(required);
        
        UPConfig config = mock(UPConfig.class);
        when(config.getAttribute("email")).thenReturn(attribute);
        
        when(userProfileProvider.getConfiguration()).thenReturn(config);
    }

    /**
     * Mock the SimpleHttp call chain used by {@code doGetFederatedIdentity} so
     * tests can provide an XML response string without making real HTTP requests.
     */
    private BrokeredIdentityContext invokeDoGetFederatedIdentityWithXml(String xmlResponse, String accessToken)
            throws Exception {
        when(config.getUserInfoUrl()).thenReturn("https://example.com/userinfo");
        when(config.getAlias()).thenReturn("gsis-taxis");

        SimpleHttp simpleHttpMock = mock(SimpleHttp.class);
        SimpleHttpRequest requestMock = mock(SimpleHttpRequest.class);
        LoginFormsProvider loginFormsProviderMock = mock(LoginFormsProvider.class);

        // Mock LoginFormsProvider for ErrorPage.error() calls
        when(session.getProvider(LoginFormsProvider.class)).thenReturn(loginFormsProviderMock);
        when(loginFormsProviderMock.setAuthenticationSession(null)).thenReturn(loginFormsProviderMock);
        when(loginFormsProviderMock.setError(anyString())).thenReturn(loginFormsProviderMock);
        when(loginFormsProviderMock.createErrorPage(any())).thenReturn(null);

        try (MockedStatic<SimpleHttp> mocked = mockStatic(SimpleHttp.class)) {
            mocked.when(() -> SimpleHttp.create(session)).thenReturn(simpleHttpMock);
            when(simpleHttpMock.doGet("https://example.com/userinfo")).thenReturn(requestMock);
            when(requestMock.header("Authorization", "Bearer " + accessToken)).thenReturn(requestMock);
            when(requestMock.asString()).thenReturn(xmlResponse);

            return provider.doGetFederatedIdentity(accessToken);
        }
    }

    @Test
    void testParseValidXml() throws Exception {
        BrokeredIdentityContext brokeredIdentityContext = invokeDoGetFederatedIdentityWithXml(TestProfile.VALID.xml(),
                "FAKE_TOKEN");

        assertNotNull(brokeredIdentityContext);
        assertEquals(TestProfile.VALID.getUsername(), brokeredIdentityContext.getUsername());
        assertEquals(TestProfile.VALID.getFirstname(), brokeredIdentityContext.getFirstName());
        assertEquals(TestProfile.VALID.getLastname(), brokeredIdentityContext.getLastName());
        assertEquals("", brokeredIdentityContext.getEmail());

        // Check context data map contains expected values
        Map<String, Set<String>> contextData = ExternalAttributeExtractor.extractAll(brokeredIdentityContext);
        assertNotNull(contextData, "Context Data map should not be null");
        assertTrue(contextData.getOrDefault("firstname", Set.of()).contains(TestProfile.VALID.getFirstname()));
        assertTrue(contextData.getOrDefault("fathername", Set.of()).contains(TestProfile.VALID.getFathername()));
        assertTrue(contextData.getOrDefault("birthyear", Set.of()).contains(TestProfile.VALID.getBirthyear()));
        assertTrue(contextData.getOrDefault("taxid", Set.of()).contains(TestProfile.VALID.getTaxid()));
        assertTrue(contextData.getOrDefault("mothername", Set.of()).contains(TestProfile.VALID.getMothername()));
        assertTrue(contextData.getOrDefault("userid", Set.of()).contains(TestProfile.VALID.getUserid()));
        assertTrue(contextData.getOrDefault("lastname", Set.of()).contains(TestProfile.VALID.getLastname()));

        // verify UserInfo JSON blob contains expected substrings
        Set<String> userInfoSet = contextData.getOrDefault("UserInfo", Set.of());
        assertFalse(userInfoSet.isEmpty(), "UserInfo entry should be present");
        String userInfoJson = userInfoSet.iterator().next();
        assertTrue(userInfoJson.contains(TestProfile.VALID.getFirstname()));
        assertTrue(userInfoJson.contains(TestProfile.VALID.getFathername()));
        assertTrue(userInfoJson.contains(TestProfile.VALID.getBirthyear()));
        assertTrue(userInfoJson.contains(TestProfile.VALID.getTaxid()));
        assertTrue(userInfoJson.contains(TestProfile.VALID.getMothername()));
        assertTrue(userInfoJson.contains(TestProfile.VALID.getUserid()));
        assertTrue(userInfoJson.contains(TestProfile.VALID.getLastname()));
    }

    @Test
    void testParseValidXmlWith11DigitTin() throws Exception {
        BrokeredIdentityContext brokeredIdentityContext = invokeDoGetFederatedIdentityWithXml(
                TestProfile.VALID_TIN_DOUBLE_ZERO.xml(),
                "FAKE_TOKEN");

        assertNotNull(brokeredIdentityContext);
        assertEquals(TestProfile.VALID_TIN_DOUBLE_ZERO.getUsername(), brokeredIdentityContext.getUsername());
        assertEquals(TestProfile.VALID_TIN_DOUBLE_ZERO.getFirstname(), brokeredIdentityContext.getFirstName());
        assertEquals(TestProfile.VALID_TIN_DOUBLE_ZERO.getLastname(), brokeredIdentityContext.getLastName());

        Map<String, Set<String>> contextData = ExternalAttributeExtractor.extractAll(brokeredIdentityContext);
        assertNotNull(contextData, "Context Data map should not be null");
        assertTrue(contextData.containsKey("taxid"));
        assertTrue(contextData.getOrDefault("taxid", Set.of())
                .contains(TestProfile.VALID_TIN_DOUBLE_ZERO.getNormalizedTaxid()));
    }

    @Test
    void testParseInvalidTinXml() throws Exception {
        assertThrows(Exception.class,
                () -> invokeDoGetFederatedIdentityWithXml(TestProfile.INVALID_TIN.xml(), "FAKE_TOKEN"));
    }

    @Test
    void testParseMalformedXml() {
        assertThrows(IdentityBrokerException.class,
                () -> invokeDoGetFederatedIdentityWithXml(TestProfile.MALFORMED.xml(), "FAKE_TOKEN"));
    }

    @Test
    void testParseEmptyXml() {
        assertThrows(IdentityBrokerException.class,
                () -> invokeDoGetFederatedIdentityWithXml(TestProfile.EMPTY.xml(), "FAKE_TOKEN"));
    }

    @Test
    void testParseXmlWithoutUserinfoElement() throws Exception {
        assertThrows(Exception.class,
                () -> invokeDoGetFederatedIdentityWithXml(TestProfile.WITHOUT_USERINFO.xml(), "FAKE_TOKEN"));
    }

    @Test
    void testParseValidXmlWithSpecialCharacters() throws Exception {
        BrokeredIdentityContext brokeredIdentityContext = invokeDoGetFederatedIdentityWithXml(
                TestProfile.SPECIAL_CHARS.xml(), "FAKE_TOKEN");

        assertNotNull(brokeredIdentityContext);
        assertEquals(TestProfile.SPECIAL_CHARS.getUsername(), brokeredIdentityContext.getUsername());
        assertEquals(TestProfile.SPECIAL_CHARS.getFirstname(), brokeredIdentityContext.getFirstName());
        assertEquals(TestProfile.SPECIAL_CHARS.getLastname(), brokeredIdentityContext.getLastName());
    }

    @Test
    void testParseXmlWithNullTaxId() throws Exception {
        assertThrows(Exception.class,
                () -> invokeDoGetFederatedIdentityWithXml(TestProfile.NULL_TAXID.xml(), "FAKE_TOKEN"));
    }

    @Test
    void testExtractIdentityFromProfile_ValidJsonProfile() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String jsonProfile = "{\"userid\":\"" + TestProfile.VALID.getUsername()
                + "\",\"firstname\":\"" + TestProfile.VALID.getFirstname()
                + "\",\"lastname\":\"" + TestProfile.VALID.getLastname() + "\"}";
        JsonNode profile = mapper.readTree(jsonProfile);

        when(config.getAlias()).thenReturn("gsis-taxis");

        BrokeredIdentityContext brokeredIdentityContext = provider.extractIdentityFromProfile(null, profile);

        assertNotNull(brokeredIdentityContext);
        assertEquals(TestProfile.VALID.getUsername(), brokeredIdentityContext.getUsername());
        assertEquals(TestProfile.VALID.getFirstname(), brokeredIdentityContext.getFirstName());
        assertEquals(TestProfile.VALID.getLastname(), brokeredIdentityContext.getLastName());
        assertEquals("", brokeredIdentityContext.getEmail());
    }

    @Test
    void testExtractIdentityFromProfile_ValidJsonProfileWithPlaceholderEmail() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String jsonProfile = "{\"userid\":\"" + TestProfile.VALID.getUsername()
                + "\",\"firstname\":\"" + TestProfile.VALID.getFirstname()
                + "\",\"lastname\":\"" + TestProfile.VALID.getLastname() + "\"}";
        JsonNode profile = mapper.readTree(jsonProfile);

        when(config.getAlias()).thenReturn("gsis-taxis");
        when(config.isGeneratePlaceholderEmail()).thenReturn(true);

        // Setup UserProfileProvider mock to return true for email requirement
        setupMockConfig(true);

        BrokeredIdentityContext brokeredIdentityContext = provider.extractIdentityFromProfile(null, profile);

        assertNotNull(brokeredIdentityContext);
        assertEquals(TestProfile.VALID.getUsername(), brokeredIdentityContext.getUsername());
        assertEquals(TestProfile.VALID.getFirstname(), brokeredIdentityContext.getFirstName());
        assertEquals(TestProfile.VALID.getLastname(), brokeredIdentityContext.getLastName());
        assertEquals(TestProfile.VALID.getUsername() + "@gsis", brokeredIdentityContext.getEmail());
    }
}
