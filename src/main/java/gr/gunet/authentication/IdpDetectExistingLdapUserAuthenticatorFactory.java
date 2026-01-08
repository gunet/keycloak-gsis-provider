package gr.gunet.authentication;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class IdpDetectExistingLdapUserAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "idp-detect-existing-ldap-user";
    private static final IdpDetectExistingLdapUserAuthenticator SINGLETON = new IdpDetectExistingLdapUserAuthenticator();

    public static final String ENABLE_LDAP_SUBSTRING_SEARCH = "enableLdapSubstringSearch";
    public static final String EXTERNAL_ATTR = "externalAttribute";
    public static final String BLOCK_USERS = "blockInvalidUsers";
    public static final String ALLOW_NULL_LDAP_ATTRIBUTE = "allowNULLLDAPAttribute";
    public static final String DEBUG_LOG = "debug.log.attributes";
    public static final String LDAP_ATTR = "ldapAttribute";
    public static final String LDAP_SEARCH_PATTERN = "ldapSearchPattern";
    public static final String LDAP_VALIDATE_ATTR = "ldapValidateAttribute";
    public static final String EXTERNAL_VALIDATE_ATTR = "externalValidateAttribute";
    public static final String LEVENSHTEIN_THRESHOLD = "levenshteinThreshold";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty externalAttr = new ProviderConfigProperty();
        externalAttr.setName(EXTERNAL_ATTR);
        externalAttr.setLabel("External IDP Attribute");
        externalAttr.setType(ProviderConfigProperty.STRING_TYPE);
        externalAttr.setRequired(true);
        externalAttr.setHelpText(
                "The name of the attribute from the external Identity Provider to use (e.g., VAT number, unique ID, or username).");
        CONFIG_PROPERTIES.add(externalAttr);

        ProviderConfigProperty ldapAttr = new ProviderConfigProperty();
        ldapAttr.setName(LDAP_ATTR);
        ldapAttr.setLabel("LDAP Search Attribute");
        ldapAttr.setType(ProviderConfigProperty.STRING_TYPE);
        ldapAttr.setRequired(true);
        ldapAttr.setHelpText("The name of the LDAP attribute used to match the user (e.g., uid, vatNumber, or mail).");
        CONFIG_PROPERTIES.add(ldapAttr);

        ProviderConfigProperty searchPattern = new ProviderConfigProperty();
        searchPattern.setName(LDAP_SEARCH_PATTERN);
        searchPattern.setLabel("LDAP Search Pattern");
        searchPattern.setType(ProviderConfigProperty.STRING_TYPE);
        searchPattern.setRequired(false);
        searchPattern.setHelpText(
                "Optional pattern for constructing LDAP search values. Use {TIN_NUMBER} placeholder" +
                        "that will be replaced with the external attribute value. Example: urn:mace:example:org:{TIN_NUMBER}:GR");
        CONFIG_PROPERTIES.add(searchPattern);

        ProviderConfigProperty enableSubstring = new ProviderConfigProperty();
        enableSubstring.setName(ENABLE_LDAP_SUBSTRING_SEARCH);
        enableSubstring.setLabel("Enable LDAP Substring Search");
        enableSubstring.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        enableSubstring.setDefaultValue(Boolean.FALSE.toString());
        enableSubstring.setHelpText(
                "NOT RECOMMENDED: When enabled, it will search on the LDAP " +
                        "Object's attribute value using substring. e.g., *TIN_NUMBER*.");
        // Uncomment to get option for substring search
        // CONFIG_PROPERTIES.add(enableSubstring);

        ProviderConfigProperty validationExternalAttr = new ProviderConfigProperty();
        validationExternalAttr.setName(EXTERNAL_VALIDATE_ATTR);
        validationExternalAttr.setLabel("Validation: External IDP Attribute");
        validationExternalAttr.setType(ProviderConfigProperty.STRING_TYPE);
        validationExternalAttr.setRequired(false);
        validationExternalAttr.setHelpText(
                "The name of the attribute from the external Identity Provider " +
                        "to use for validating the user (e.g., lastname or firstname). If it is empty, no validation will be performed.");
        CONFIG_PROPERTIES.add(validationExternalAttr);

        ProviderConfigProperty validationLdapAttr = new ProviderConfigProperty();
        validationLdapAttr.setName(LDAP_VALIDATE_ATTR);
        validationLdapAttr.setLabel("Validation: LDAP Attribute");
        validationLdapAttr.setType(ProviderConfigProperty.STRING_TYPE);
        validationLdapAttr.setRequired(false);
        validationLdapAttr.setHelpText(
                "The name of the LDAP attribute used to validate the user from the external " +
                        "IDP (e.g., lastname or firstname). If configured, the value from the external IDP " +
                        "will be compared against the LDAP attribute value to ensure they match. If it is empty, no validation will be performed.");
        CONFIG_PROPERTIES.add(validationLdapAttr);

        ProviderConfigProperty levenshteinThreshold = new ProviderConfigProperty();
        levenshteinThreshold.setName(LEVENSHTEIN_THRESHOLD);
        levenshteinThreshold.setLabel("Validation Threshold");
        levenshteinThreshold.setType(ProviderConfigProperty.INTEGER_TYPE);
        levenshteinThreshold.setHelpText(
                "Optional. Defines the maximum allowed Levenshtein distance between validation attributes " +
                        "to be considered a match (e.g., 1 allows one-character difference, on ΠΑΠΑΔΟΠΟΥΛΟ and ΠΑΠΑΔΟΠΟΥΛΟΣ will be matched). Default is 0 (exact match).");
        levenshteinThreshold.setDefaultValue("0");
        levenshteinThreshold.setRequired(false);
        CONFIG_PROPERTIES.add(levenshteinThreshold);

        ProviderConfigProperty blockUsers = new ProviderConfigProperty();
        blockUsers.setName(BLOCK_USERS);
        blockUsers.setLabel("Block Invalid Users");
        blockUsers.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        blockUsers.setHelpText("If enabled, any user who does not pass the validation checks will be denied authentication.");
        CONFIG_PROPERTIES.add(blockUsers);

        ProviderConfigProperty allowNULL = new ProviderConfigProperty();
        allowNULL.setName(ALLOW_NULL_LDAP_ATTRIBUTE);
        allowNULL.setLabel("Allow NULL LDAP Attribute");
        allowNULL.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        allowNULL.setDefaultValue(Boolean.toString(true));
        allowNULL.setHelpText("If enabled, users whose LDAP attribute is missing or NULL will still be allowed to authenticate.");
        CONFIG_PROPERTIES.add(allowNULL);

        ProviderConfigProperty debugLog = new ProviderConfigProperty();
        debugLog.setName(DEBUG_LOG);
        debugLog.setLabel("Enable debug logging");
        debugLog.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        debugLog.setHelpText("When enabled, logs all available IDP attributes and context data during login.");
        CONFIG_PROPERTIES.add(debugLog);
    }

    @Override
    public String getDisplayType() {
        return "Detect Existing LDAP User via External IDP";
    }

    @Override
    public String getReferenceCategory() {
        return "detectExistingLdapUser";
    }

    @Override
    public String getHelpText() {
        return "Detects an existing LDAP user in the realm using a configured attribute from an external IDP without creating new users.";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
