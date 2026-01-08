package gr.gunet.broker.gsis;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.userprofile.config.UPAttributeRequired;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.helpers.DefaultHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import gr.gunet.utils.Validator;
import gr.gunet.services.messages.GsisReconciliationMessages;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

public class GsisIdentityProvider extends AbstractOAuth2IdentityProvider<GsisIdentityProviderConfig> {

    protected static final Logger LOGGER = Logger.getLogger(GsisIdentityProvider.class);

    public static final String FEDERATED_ID_TOKEN = "FEDERATED_ID_TOKEN";
    public static final String GSIS_TIN = "taxid";
    public static final String GSIS_USERID = "userid";
    public static final String GSIS_LASTNAME = "lastname";
    public static final String GSIS_FIRSTNAME = "firstname";
    public static final String GSIS_FATHERNAME = "fathername";
    public static final String GSIS_MOTHERNAME = "mothername";
    public static final String GSIS_BIRTHYEAR = "birthyear";

    public GsisIdentityProvider(KeycloakSession session,
            GsisIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new OIDCEndpoint(callback, realm, event, this);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event,
            JsonNode profile) {
        String username = getJsonProperty(profile, GSIS_USERID);
        String firstname = getJsonProperty(profile, GSIS_FIRSTNAME);
        String lastname = getJsonProperty(profile, GSIS_LASTNAME);

        GsisIdentityProviderConfig config = getConfig();
        BrokeredIdentityContext user = new BrokeredIdentityContext(username, config);

        // Check if Email Attribute is required
        UserProfileProvider userProfileProvider = session.getProvider(UserProfileProvider.class);
        UPAttributeRequired AttributeEmailRequired = userProfileProvider.getConfiguration().getAttribute("email").getRequired();


        user.setUsername(getConfig().isGenerateScopedUsernameEnabled() ? username + "@gsis" : username);
        user.setFirstName(firstname);
        user.setLastName(lastname);
        user.setEmail(getConfig().isGeneratePlaceholderEmail() && AttributeEmailRequired != null ? username.toLowerCase() + "@gsis" : "");
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, config.getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        String profileUrl = getConfig().getUserInfoUrl();
        String jsonStringProfile = "";

        try {
            SimpleHttpRequest request = SimpleHttp.create(session).doGet(profileUrl);
            String profile = request.header("Authorization", "Bearer " + accessToken).asString();

            final Map<String, String> userFields = new HashMap<String, String>();
            SAXParser parser = getXMLParser();

            parser.parse(new InputSource(new StringReader(profile)), new DefaultHandler() {
                @Override
                public void startElement(String uri, String localName, String qName, Attributes attributes)
                        throws SAXException {
                    if ("userinfo".equals(qName)) {
                        userFields.put(GSIS_USERID, Validator.normalizeString(attributes.getValue(GSIS_USERID)));
                        userFields.put(GSIS_TIN, Validator.normalizeTin(attributes.getValue(GSIS_TIN)));
                        userFields.put(GSIS_LASTNAME, Validator.normalizeString(attributes.getValue(GSIS_LASTNAME)));
                        userFields.put(GSIS_FIRSTNAME, Validator.normalizeString(attributes.getValue(GSIS_FIRSTNAME)));
                        userFields.put(GSIS_FATHERNAME,
                                Validator.normalizeString(attributes.getValue(GSIS_FATHERNAME)));
                        userFields.put(GSIS_MOTHERNAME,
                                Validator.normalizeString(attributes.getValue(GSIS_MOTHERNAME)));
                        userFields.put(GSIS_BIRTHYEAR, Validator.normalizeString(attributes.getValue(GSIS_BIRTHYEAR)));
                    }
                }
            });

            if (!Validator.checkTin(userFields.get(GSIS_TIN))) {
                throw new IdentityBrokerException("Invalid TIN received from GSIS: " + userFields.get(GSIS_TIN));
            }

            ObjectMapper mapper = new ObjectMapper();
            jsonStringProfile = mapper.writeValueAsString(userFields);
            JsonNode jsonProfile = mapper.readTree(jsonStringProfile);

            return extractIdentityFromProfile(null, jsonProfile);
        } catch (IdentityBrokerException ibe) {
            LOGGER.error("IdentityBrokerException while obtaining user profile from gsis", ibe);
            Response error = ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
                    GsisReconciliationMessages.VALIDATION_ERROR);
            throw new ErrorPageException(error);
        } catch (Exception e) {
            LOGGER.error("Exception while obtaining user profile from gsis", e);
            throw new IdentityBrokerException(
                    "Could not obtain user profile from gsis.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return "";
    }

    private String getIDTokenForLogout(KeycloakSession session, UserSessionModel userSession) {
        String tokenExpirationString = userSession.getNote(FEDERATED_TOKEN_EXPIRATION);
        long expirationTime = tokenExpirationString == null ? 0 : Long.parseLong(tokenExpirationString);
        int currentTime = Time.currentTime();

        if (expirationTime > 0 && currentTime > expirationTime) {
            String response = refreshTokenForLogout(session, userSession);
            AccessTokenResponse tokenResponse = null;

            try {
                tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            return tokenResponse.getIdToken();
        }

        return userSession.getNote(FEDERATED_ID_TOKEN);
    }

    protected static class OIDCEndpoint extends Endpoint {
        public OIDCEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event,
                AbstractOAuth2IdentityProvider<GsisIdentityProviderConfig> provider) {
            super(callback, realm, event, provider);
        }

        @Override
        public SimpleHttpRequest generateTokenRequest(String authorizationCode) {
            SimpleHttpRequest simpleHttp = super.generateTokenRequest(authorizationCode);
            return simpleHttp;
        }

        @GET
        @Path("logout_response")
        public Response logoutResponse(@QueryParam("state") String state) {
            if (state == null) {
                LOGGER.error("No state parameter in logout response");
                EventBuilder event = new EventBuilder(realm, session, clientConnection);
                event.event(EventType.LOGOUT);
                event.error(Errors.USER_SESSION_NOT_FOUND);

                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
                        Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            UserSessionModel userSession = session.sessions().getUserSession(realm, state);
            if (userSession == null) {
                LOGGER.errorf("No user session found for state %s", state);
                EventBuilder event = new EventBuilder(realm, session, clientConnection);
                event.event(EventType.LOGOUT);
                event.error(Errors.USER_SESSION_NOT_FOUND);

                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
                        Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
                LOGGER.error("The user session is in a different state");
                EventBuilder event = new EventBuilder(realm, session, clientConnection);
                event.event(EventType.LOGOUT);
                event.error(Errors.USER_SESSION_NOT_FOUND);

                return ErrorPage.error(session, null, Response.Status.BAD_REQUEST,
                        Messages.SESSION_NOT_ACTIVE);
            }

            return AuthenticationManager.finishBrowserLogout(session, realm, userSession,
                    session.getContext().getUri(), clientConnection, headers);
        }
    }

    /**
     * Creates a XML parser using SAXParser with configured mitigated XXE attacks
     * 
     * @return The configured SAXParser
     * @throws ParserConfigurationException Thrown if a parser configuration error
     *                                      occurs
     * @throws SAXException                 Thrown if a SAX error occurs
     * @see https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
     */
    private SAXParser getXMLParser() throws ParserConfigurationException, SAXException {
        // XML External Entity (XXE) Prevention:
        HashMap<String, String> features = new HashMap<>();
        features.put(XMLConstants.FEATURE_SECURE_PROCESSING, "true");
        features.put("http://apache.org/xml/features/disallow-doctype-decl", "true");
        features.put("http://xml.org/sax/features/external-general-entities", "false");
        features.put("http://xml.org/sax/features/external-parameter-entities", "false");

        SAXParserFactory parserFactory = SAXParserFactory.newInstance();
        parserFactory.setValidating(false);
        parserFactory.setXIncludeAware(false);
        parserFactory.setNamespaceAware(false);
        for (Map.Entry<String, String> feature : features.entrySet()) {
            try {
                parserFactory.setFeature(feature.getKey(), Boolean.parseBoolean(feature.getValue()));
            } catch (ParserConfigurationException e) {
                // An unsupported feature.
                LOGGER.error("An unsupported feature was set on the SAX Parser Factory", e);
            } catch (SAXNotRecognizedException e) {
                // Tried an unknown feature.
                LOGGER.error("An unrecognized feature was set on the SAX Parser Factory", e);
            } catch (SAXNotSupportedException e) {
                // Tried a feature known to the parser but unsupported.
                LOGGER.error("An unsupported feature was set on the SAX Parser Factory", e);
            }
        }

        return parserFactory.newSAXParser();
    }

    /**
     * Returns access token response as a string from a refresh token invocation on
     * the remote OIDC broker
     *
     * @param session     The Keycloak session
     * @param userSession The user session
     * @return The access token response as a string
     */
    public String refreshTokenForLogout(KeycloakSession session, UserSessionModel userSession) {
        String refreshToken = userSession.getNote(FEDERATED_REFRESH_TOKEN);
        GsisIdentityProviderConfig config = getConfig();
        String clientSecret = config.getClientSecret();

        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(clientSecret)) {
            return getRefreshTokenRequest(session, refreshToken, config.getClientId(),
                    vaultStringSecret.get().orElse(clientSecret)).asString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates a SimpleHttpRequest for a refresh token request to the remote OIDC
     * broker
     * 
     * @param session      The Keycloak session
     * @param refreshToken The refresh token
     * @param clientId     The client ID
     * @param clientSecret The client secret
     * @return The SimpleHttpRequest for the refresh token
     */
    protected SimpleHttpRequest getRefreshTokenRequest(KeycloakSession session, String refreshToken,
            String clientId, String clientSecret) {
        SimpleHttpRequest refreshTokenRequest = SimpleHttp.create(session).doPost(getConfig().getTokenUrl())
                .param(OAUTH2_GRANT_TYPE_REFRESH_TOKEN, refreshToken)
                .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_REFRESH_TOKEN);

        return authenticateTokenRequest(refreshTokenRequest);
    }

    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
            UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        String logoutUrl = getConfig().getLogoutUrl();

        if (logoutUrl == null || logoutUrl.trim().length() == 0) {
            return null;
        }

        String idToken = getIDTokenForLogout(session, userSession);
        String sessionId = userSession.getId();
        UriBuilder logoutUri = UriBuilder.fromUri(logoutUrl).queryParam("state", sessionId);

        if (idToken != null) {
            logoutUri.queryParam("id_token_hint", idToken);
        }

        GsisIdentityProviderConfig config = getConfig();
        String redirect = RealmsResource.brokerUrl(uriInfo)
                .path(IdentityBrokerService.class, "getEndpoint").path(OIDCEndpoint.class, "logoutResponse")
                .queryParam("state", sessionId).build(realm.getName(), config.getAlias()).toString();
        logoutUri.queryParam("url", redirect);

        return Response.status(302).location(logoutUri.build(config.getClientId())).build();
    }
}