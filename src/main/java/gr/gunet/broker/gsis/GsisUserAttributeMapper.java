package gr.gunet.broker.gsis;

import java.util.List;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.provider.ProviderConfigProperty;

public class GsisUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    public static final String PROVIDER_ID = "gsis-user-attribute-mapper";
    private static final String[] compatibleProviders = new String[] {
            GsisIdentityProviderFactory.PROVIDER_ID };

    private static List<String> gsisUserProfileStrings = List.of(
            GsisIdentityProvider.GSIS_TIN,
            GsisIdentityProvider.GSIS_USERID,
            GsisIdentityProvider.GSIS_LASTNAME,
            GsisIdentityProvider.GSIS_FIRSTNAME,
            GsisIdentityProvider.GSIS_FATHERNAME,
            GsisIdentityProvider.GSIS_MOTHERNAME,
            GsisIdentityProvider.GSIS_BIRTHYEAR);

    @Override
    public String[] getCompatibleProviders() {
        return compatibleProviders;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = super.getConfigProperties();
        for (ProviderConfigProperty property : configProperties) {
            if (property.getName().equals(CONF_JSON_FIELD)) {
                property.setLabel("GSIS User Profile Field");
                property.setHelpText(
                        "Select the GSIS user profile field to map to the user attribute.");
                property.setType(ProviderConfigProperty.LIST_TYPE);
                property.setOptions(gsisUserProfileStrings);
                break;
            }
        }
        return configProperties;
    }

    @Override
    public String getHelpText() {
        return "Import user profile information if it exists in GSIS JSON data into the specified user attribute.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
