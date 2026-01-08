package gr.gunet.authentication;

import gr.gunet.services.messages.GsisReconciliationMessages;
import gr.gunet.utils.ExternalAttributeExtractor;
import gr.gunet.utils.LDAPSearchUtils;
import gr.gunet.utils.Validator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.services.ErrorPage;

import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public class IdpDetectExistingLdapUserAuthenticator extends AbstractIdpAuthenticator {

    private static final String SESSION_NOTE_ORIGINAL_USER_ID = "original_user_id";
    private static final Logger logger = Logger.getLogger(IdpDetectExistingLdapUserAuthenticator.class);

    // Configuration variables for internal use
    private String externalAttrName = "";
    private String ldapAttrName = "";
    private String ldapSearchPattern = "";
    private boolean bBlockInvalidUsers = false;
    private boolean bAllowNullLDAPAttribute = true;
    private boolean bShowDebugLogsAsInfo = false;
    private boolean bEnableLdapSubstringSearch = false;
    private String externalValidateAttrName = "";
    private String ldapValidateAttrName = "";
    private int levenshteinThreshold;

    @Override
    protected void authenticateImpl(AuthenticationFlowContext context,
            SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();

        // Load configuration
        if (!loadConfiguration(context.getAuthenticatorConfig())) {
            context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_DISABLED);
            return;
        }

        debugLog("Context Data returned from {%s}: \n {%s}", brokerContext.getIdpConfig().getDisplayName(),
                brokerContext.getContextData().toString());
        debugLog("Attributes returned from {%s}: \n {%s}", brokerContext.getIdpConfig().getDisplayName(),
                brokerContext.getAttributes().toString());

        // Extract specified attribute values from the external IDP
        Set<String> externalValues = ExternalAttributeExtractor.extractValues(externalAttrName, brokerContext);
        if (externalValues.isEmpty()) {
            errorLog(String.format("External attribute '%s' not found anywhere in broker context.",
                    externalAttrName));
            failAuthentication(context, AuthenticationFlowError.UNKNOWN_USER, Response.Status.BAD_REQUEST,
                    Errors.USER_NOT_FOUND, GsisReconciliationMessages.USER_NOT_FOUND_ERROR);
            return;
        }
        debugLog("Collected external values for '%s': %s", externalAttrName, externalValues);

        // Search for users matching the extracted attribute values
        List<UserModel> foundUsers = findUsersByAttribute(externalValues, realm, session, ldapAttrName,
                ldapSearchPattern, bEnableLdapSubstringSearch);
        if (foundUsers.isEmpty()) {
            externalValues.removeIf(
                    v -> v == null || v.trim().isEmpty() || v.trim().equalsIgnoreCase("null"));
            warnLog("No LDAP user found for any value of '%s': %s", ldapAttrName, externalValues);
            failAuthentication(context, AuthenticationFlowError.UNKNOWN_USER, Response.Status.BAD_REQUEST,
                    Errors.USER_NOT_FOUND, GsisReconciliationMessages.USER_NOT_FOUND_ERROR);
            return;
        }
        if ((!shouldPerformValidation() && foundUsers.size() > 1) ||
                (shouldPerformValidation() && !bBlockInvalidUsers && foundUsers.size() > 1)) {
            externalValues.removeIf(
                    v -> v == null || v.trim().isEmpty() || v.trim().equalsIgnoreCase("null"));
            warnLog("Multiple LDAP users found for '%s' values: %s", ldapAttrName, externalValues);
            failAuthentication(context, AuthenticationFlowError.USER_CONFLICT, Response.Status.BAD_REQUEST,
                    Errors.NOT_ALLOWED, GsisReconciliationMessages.VALIDATION_ERROR);
            return;
        }

        final UserModel ldapUser = resolveLdapUser(foundUsers, brokerContext);
        if (ldapUser == null) {
            failAuthentication(context, AuthenticationFlowError.UNKNOWN_USER,
                    Response.Status.BAD_REQUEST,
                    Errors.NOT_ALLOWED, GsisReconciliationMessages.VALIDATION_ERROR);
            return;
        }

        debugLog("Matched user '%s' using %s in %s", ldapUser.getUsername(), externalValues,
                realm.getName());

        // Store info about the existing user for downstream authenticators/mappers
        ExistingUserInfo existingUserInfo = new ExistingUserInfo(ldapUser.getId(), ldapAttrName,
                String.join(",", externalValues));
        context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, existingUserInfo.serialize());

        if (brokerContext.getIdpConfig().isTransientUsers()) {
            LightweightUserAdapter lightweightUser = createLightweightUserAdapter(session, realm,
                    ldapUser);
            context.getAuthenticationSession().setUserSessionNote(SESSION_NOTE_ORIGINAL_USER_ID,
                    ldapUser.getId());
            context.setUser(lightweightUser);
            context.getAuthenticationSession().setAuthenticatedUser(lightweightUser);
            // Run Our Custom Mapper for the LightWeight User
            session.identityProviders().getMappersByAliasStream(brokerContext.getIdpConfig().getAlias())
                    .forEach(mapperModel -> {
                        var factory = (IdentityProviderMapper) session
                                .getKeycloakSessionFactory().getProviderFactory(
                                        IdentityProviderMapper.class,
                                        mapperModel.getIdentityProviderMapper());

                        if (factory == null) {
                            warnLog("Mapper factory not found for mapper %s",
                                    mapperModel.getName());
                            return;
                        }

                        if ("idp-attribute-session-mapper"
                                .equals(mapperModel.getIdentityProviderMapper())) {
                            factory.updateBrokeredUser(session, realm, ldapUser,
                                    mapperModel, brokerContext);
                            debugLog("Executed IDP mapper %s for user %s",
                                    mapperModel.getName(),
                                    ldapUser.getUsername());
                        }
                    });
        } else {
            context.setUser(ldapUser);
            context.getAuthenticationSession().setAuthenticatedUser(ldapUser);
        }
        context.success();
    }

    @Override
    protected void actionImpl(AuthenticationFlowContext context,
            SerializedBrokeredIdentityContext serializedCtx,
            BrokeredIdentityContext brokerContext) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void close() {
    }

    /**
     * Determines whether LDAP user validation should be performed.
     * Validation is enabled only when both the external validation
     * attribute name and the LDAP validation attribute name have
     * been configured with non-empty values.
     *
     * @return true if both validation-related attributes are configured and
     *         validation logic should run, otherwise false
     */
    private boolean shouldPerformValidation() {
        return !externalValidateAttrName.trim().isEmpty()
                && !ldapValidateAttrName.trim().isEmpty();
    }

    /**
     * Loads and parses authenticator configuration values from the provided
     * {@link AuthenticatorConfigModel}.
     *
     * <p>
     * This method reads the configuration keys from
     * {@link IdpDetectExistingLdapUserAuthenticatorFactory} and sets the
     * corresponding private fields in the authenticator. It also performs basic
     * validation on certain keys, such as checking that the LDAP search pattern
     * contains the required placeholder.
     *
     * <p>
     * Behavior:
     * <ul>
     * <li>If {@code cfg} or {@code cfg.getConfig()} is {@code null}, the method
     * logs an error and returns {@code false}.</li>
     * <li>Missing keys are replaced with sensible defaults
     * (empty strings, false, or 0).</li>
     * <li>Boolean and integer values are parsed
     * from their string representation.</li>
     * <li>If {@code ldapSearchPattern} is provided but does not contain the
     * required placeholder, a debug warning is logged.</li>
     * <li>If the essential keys {@code externalAttrName}
     * or {@code ldapAttrName} are missing, an error is logged and the method
     * returns {@code false}.</li>
     * </ul>
     *
     * @param cfg the authenticator config model containing the configuration map
     * @return {@code true} if configuration was successfully loaded and contains
     *         the required keys; {@code false} otherwise
     */
    private boolean loadConfiguration(AuthenticatorConfigModel cfg) {
        if (cfg == null || cfg.getConfig() == null) {
            errorLog("Authenticator not properly configured.");
            return false;
        }
        externalAttrName = cfg.getConfig()
                .get(IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_ATTR);
        ldapAttrName = cfg.getConfig().get(IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_ATTR);
        ldapSearchPattern = cfg.getConfig()
                .getOrDefault(IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_SEARCH_PATTERN, "");
        bBlockInvalidUsers = Boolean.parseBoolean(
                cfg.getConfig().getOrDefault(IdpDetectExistingLdapUserAuthenticatorFactory.BLOCK_USERS,
                        "false"));
        bAllowNullLDAPAttribute = Boolean.parseBoolean(
                cfg.getConfig().getOrDefault(
                        IdpDetectExistingLdapUserAuthenticatorFactory.ALLOW_NULL_LDAP_ATTRIBUTE,
                        "true"));
        bShowDebugLogsAsInfo = Boolean.parseBoolean(
                cfg.getConfig().getOrDefault(IdpDetectExistingLdapUserAuthenticatorFactory.DEBUG_LOG,
                        "false"));
        bEnableLdapSubstringSearch = Boolean.parseBoolean(cfg.getConfig()
                .getOrDefault(IdpDetectExistingLdapUserAuthenticatorFactory.ENABLE_LDAP_SUBSTRING_SEARCH,
                        "false"));
        externalValidateAttrName = cfg.getConfig()
                .getOrDefault(IdpDetectExistingLdapUserAuthenticatorFactory.EXTERNAL_VALIDATE_ATTR, "");
        ldapValidateAttrName = cfg.getConfig()
                .getOrDefault(IdpDetectExistingLdapUserAuthenticatorFactory.LDAP_VALIDATE_ATTR, "");
        levenshteinThreshold = Integer.parseInt(
                cfg.getConfig().getOrDefault(
                        IdpDetectExistingLdapUserAuthenticatorFactory.LEVENSHTEIN_THRESHOLD,
                        "0"));

        if (!ldapSearchPattern.trim().isEmpty() && !ldapSearchPattern.contains("{TIN_NUMBER}")) {
            debugLog(
                    "LDAP Search Pattern '%s' does not contain the required placeholder {TIN_NUMBER}. It will be ignored.",
                    ldapSearchPattern);
        }

        if (externalAttrName == null || ldapAttrName == null) {
            errorLog("Missing configuration for 'externalAttribute' or 'ldapAttribute'.");
            return false;
        }
        return true;
    }

    /**
     * Helper method for error logging.
     * 
     * @param message The log message
     */
    private void errorLog(String message) {
        logger.error("[Reconciliation Authenticator] " + message);
    }

    /**
     * Helper method for warning logging.
     * 
     * @param format The log message format
     * @param params The parameters for the log message
     */
    private void warnLog(String format, Object... params) {
        logger.warnf("[Reconciliation Authenticator] " + format, params);
    }

    /**
     * Helper method for debug logging, that respects the configuration to log as
     * INFO or DEBUG.
     * 
     * @param format The log message format
     * @param params The parameters for the log message
     */
    private void debugLog(String format, Object... params) {
        String prefix = "[Reconciliation Authenticator] ";
        if (bShowDebugLogsAsInfo) {
            logger.infof("[DEBUG] " + prefix + format, params);
        } else {
            logger.debugf(prefix + format, params);
        }
    }

    /**
     * Helper method to fail authentication with a custom error page and event
     * logging.
     * 
     * @param context        The authentication flow context
     * @param flowError      The authentication flow error
     * @param responseStatus The HTTP response status
     * @param eventError     The event error code should be Errors interface
     * @param messageKey     The message key for the error page
     */
    private void failAuthentication(AuthenticationFlowContext context,
            AuthenticationFlowError flowError,
            Response.Status responseStatus,
            String eventError,
            String messageKey) {
        Response errorPage = ErrorPage.error(
                context.getSession(),
                null,
                responseStatus,
                messageKey);

        context.getEvent()
                .detail("idp_reconcil_authentication_error", messageKey)
                .error(eventError);

        context.failure(flowError, errorPage);
    }

    /**
     * Resolves the correct LDAP user from the list of matches.
     *
     * <p>
     * This method applies optional validation logic using configured
     * validation attributes. If validation is enabled, only users that
     * match the validation criteria will be considered valid. If validation
     * fails, behavior depends on the configuration:
     *
     * <ul>
     * <li>If blocking invalid users is enabled, the method returns null.</li>
     * <li>If blocking is disabled, the method falls back to the first user
     * in the list.</li>
     * </ul>
     *
     * <p>
     * If validation is not enabled at all, the first found user is returned.
     *
     * @param usersList     The list of LDAP users found during the primary search
     * @param brokerContext The brokered identity context containing external IDP
     *                      attributes
     * @return The resolved UserModel if validation succeeds or fallback is allowed,
     *         otherwise null if validation fails and blocking is enabled
     */
    private UserModel resolveLdapUser(List<UserModel> usersList, BrokeredIdentityContext brokerContext) {
        // If validation is required, validate
        UserModel resolvedUser = shouldPerformValidation()
                ? findAndValidateUser(externalValidateAttrName, ldapValidateAttrName, usersList,
                        brokerContext, levenshteinThreshold)
                : usersList.get(0);

        if (resolvedUser == null) {
            warnLog("Failed to validate users using '%s': %s",
                    ldapValidateAttrName, externalValidateAttrName);

            if (bBlockInvalidUsers) {
                return null;
            }

            // Continue with the first found user if bBlockInvalidUsers is false
            resolvedUser = usersList.get(0);
        }

        return resolvedUser;
    }

    /**
     * Helper method to find and validate a user from a list of found users using
     * validation attributes.
     * 
     * @param externalValidateAttrName The external IDP attribute name used for
     *                                 validation
     * @param ldapValidateAttrName     The LDAP attribute name used for validation
     * @param foundUsers               The list of found users to validate against
     * @param brokerContext            The brokered identity context
     * @param levenshteinThreshold     The Levenshtein distance threshold for
     *                                 validation
     * @return The validated UserModel if a match is found, otherwise null
     */
    private UserModel findAndValidateUser(String externalValidateAttrName, String ldapValidateAttrName,
            List<UserModel> foundUsers, BrokeredIdentityContext brokerContext,
            int levenshteinThreshold) {
        Set<String> externalValidationValues = ExternalAttributeExtractor
                .extractValues(externalValidateAttrName, brokerContext);
        for (UserModel user : foundUsers) {
            List<String> ldapValidationValues = user.getAttributeStream(ldapValidateAttrName)
                    .toList();
            if (ldapValidationValues.isEmpty()) {
                if (bAllowNullLDAPAttribute) {
                    warnLog("User '%s' has empty LDAP attribute %s - allowing per configuration",
                            user.getUsername(),
                            ldapValidateAttrName);
                    return user;
                } else {
                    continue;
                }
            }

            boolean match = externalValidationValues.stream()
                    .anyMatch(extVal -> ldapValidationValues.stream()
                            .anyMatch(ldapVal -> {
                                return Validator.levenshteinDistance(extVal,
                                        ldapVal) <= levenshteinThreshold;
                            }));
            if (match) {
                return user;
            }
        }
        return null;
    }

    /**
     * Helper method to find users by searching for attribute values in LDAP.
     * 
     * @param externalIDPAttributeValues The set of attribute values extracted from
     *                                   the external IDP
     * @param realm                      The Keycloak realm
     * @param session                    The Keycloak session
     * @param ldapAttrName               The LDAP attribute name to search for
     * @param ldapSearchPattern          The LDAP search pattern
     * @param enableLdapSubstringSearch  Whether to enable substring search in LDAP
     * @return
     */
    private List<UserModel> findUsersByAttribute(Set<String> externalIDPAttributeValues, RealmModel realm,
            KeycloakSession session, String ldapAttrName, String ldapSearchPattern,
            boolean enableLdapSubstringSearch) {
        UserProvider userProvider = session.users();

        return externalIDPAttributeValues.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(v -> !v.isEmpty())
                .flatMap(val -> {
                    String searchVal = val;
                    if (!ldapSearchPattern.trim().isEmpty()
                            && ldapSearchPattern.contains("{TIN_NUMBER}")) {

                        searchVal = ldapSearchPattern.replace("{TIN_NUMBER}", val);
                    }
                    List<UserModel> results = userProvider
                            .searchForUserByUserAttributeStream(realm, ldapAttrName,
                                    searchVal)
                            .toList();

                    if (results.isEmpty() && enableLdapSubstringSearch) {
                        return LDAPSearchUtils.searchUserByAttributeSubstringStream(
                                userProvider, session, realm,
                                ldapAttrName, val);
                    }
                    return results.stream();
                }).toList();
    }

    /**
     * Helper method to create a LightweightUserAdapter from an existing UserModel.
     * 
     * @param session      The Keycloak session
     * @param realm        The Keycloak realm
     * @param originalUser The original UserModel to copy attributes from
     * @return The created LightweightUserAdapter
     */
    private LightweightUserAdapter createLightweightUserAdapter(KeycloakSession session, RealmModel realm,
            UserModel originalUser) {
        // We need to create a unique ID for the lightweight user to avoid conflicts
        String lightweightId = UUID.randomUUID().toString();

        LightweightUserAdapter lightweightUser = new LightweightUserAdapter(session, realm, lightweightId);
        lightweightUser.setUsername(originalUser.getUsername());
        lightweightUser.setEmail(originalUser.getEmail());
        lightweightUser.setFirstName(originalUser.getFirstName());
        lightweightUser.setLastName(originalUser.getLastName());
        originalUser.getAttributes().forEach(lightweightUser::setAttribute);
        // Add Roles from the original user to the lightweight user
        originalUser.getRealmRoleMappingsStream().forEach(lightweightUser::grantRole);
        realm.getClientsStream().forEach(client -> {
            originalUser.getClientRoleMappingsStream(client).forEach(lightweightUser::grantRole);
        });
        lightweightUser.setEnabled(originalUser.isEnabled());
        return lightweightUser;
    }
}
