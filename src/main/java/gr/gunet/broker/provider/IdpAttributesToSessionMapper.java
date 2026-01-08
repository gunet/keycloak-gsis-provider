package gr.gunet.broker.provider;

import gr.gunet.utils.ExternalAttributeExtractor;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;

public class IdpAttributesToSessionMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "idp-attribute-session-mapper";
    private static final Logger logger = Logger.getLogger(IdpAttributesToSessionMapper.class);
    private boolean showDebugLogsAsInfo = false;

    // Mapper configuration keys
    public static final String INCLUDE_ATTRIBUTES = "include.attributes";
    public static final String DEBUG_LOG = "debug.log.attributes";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty includeAttrs = new ProviderConfigProperty();
        includeAttrs.setName(INCLUDE_ATTRIBUTES);
        includeAttrs.setLabel("Attributes to include");
        includeAttrs.setHelpText("Comma-separated list of IDP attributes to store in session notes (idp_*).");
        includeAttrs.setType(STRING_TYPE);
        configProperties.add(includeAttrs);

        ProviderConfigProperty debugLog = new ProviderConfigProperty();
        debugLog.setName(DEBUG_LOG);
        debugLog.setLabel("Enable debug logging");
        debugLog.setHelpText("When enabled, logs all available IDP attributes and context data during login.");
        debugLog.setType(BOOLEAN_TYPE);
        configProperties.add(debugLog);
    }

    public static final String[] COMPATIBLE_PROVIDERS = { ANY_PROVIDER };

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return "Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "IDP Attributes to Session Notes Mapper";
    }

    @Override
    public String getHelpText() {
        return "Stores selected IDP attributes and context data (including nested or JSON values) as session notes (idp_*).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        attributesToSessionNotes(mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        attributesToSessionNotes(mapperModel, context);
    }

    /**
     * Attributes from the IDP to session notes (idp_*)
     * 
     * @param session     The Keycloak session
     * @param realm       The realm model
     * @param user        The user model
     * @param mapperModel The identity provider mapper model
     * @param context     The brokered identity context
     */
    private void attributesToSessionNotes(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        showDebugLogsAsInfo = Boolean.parseBoolean(mapperModel.getConfig().getOrDefault(DEBUG_LOG, "false"));

        debugLog("Context Data for user %s: \n {%s}", context.getUsername(), context.getContextData().toString());
        debugLog("Attributes from IDP for user %s: \n {%s}", context.getUsername(), context.getAttributes().toString());

        // Get list of attributes to include
        String includeList = mapperModel.getConfig().get(INCLUDE_ATTRIBUTES);
        Set<String> attributesToInclude = new HashSet<>();
        if (includeList != null) {
            Arrays.stream(includeList.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .forEach(attributesToInclude::add);
        }

        // For each attribute name, extract values using the utility
        for (String attrName : attributesToInclude) {
            Set<String> values = ExternalAttributeExtractor.extractValues(attrName, context);
            if (!values.isEmpty()) {
                for (String val : values) {
                    context.setSessionNote("idp_" + attrName, val);
                    debugLog("Stored IDP extracted value as session note: idp_%s = %s", attrName, val);
                }
            } else {
                debugLog("No values found for attribute '%s' in broker context.", attrName);
            }
        }

        // If include list is empty, extract everything
        if (attributesToInclude.isEmpty()) {
            Map<String, Set<String>> allValues = ExternalAttributeExtractor.extractAll(context);
            for (Map.Entry<String, Set<String>> entry : allValues.entrySet()) {
                for (String val : entry.getValue()) {
                    context.setSessionNote("idp_" + entry.getKey(), val);
                    debugLog("Stored IDP extracted value as session note: idp_%s = %s", entry.getKey(), val);
                }
            }
        }
    }

    /**
     * Helper method for debug logging, that respects the configuration to log as
     * INFO or DEBUG.
     * 
     * @param format The log message format
     * @param params The parameters for the log message
     */
    private void debugLog(String format, Object... params) {
        if (showDebugLogsAsInfo) {
            logger.infof("[IDP Mapper To Session Notes] " + format, params);
        } else {
            logger.debugf("[IDP Mapper To Session Notes] " + format, params);
        }
    }
}
