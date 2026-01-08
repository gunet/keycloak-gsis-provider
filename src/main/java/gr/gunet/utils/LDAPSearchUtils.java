package gr.gunet.utils;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.model.LDAPDn;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.idm.query.Condition;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

public class LDAPSearchUtils {
    private static final Logger logger = Logger.getLogger(LDAPSearchUtils.class);

    /**
     * Search LDAP users using a substring condition instead of exact equality.
     *
     * @param ldapProvider the LDAPStorageProvider instance
     * @param realm        Realm model
     * @param attrName     LDAP attribute name
     * @param attrValue    Substring value to search for
     * @return Stream of LDAPObject
     */
    private static Stream<LDAPObject> searchLDAPBySubstring(
            LDAPStorageProvider ldapProvider,
            RealmModel realm,
            String attrName,
            String attrValue) {
        List<LDAPObject> ldapObjects;
        if (ldapProvider == null) {
            logger.warn("LDAP provider is null, cannot perform search");
            return Stream.empty();
        }

        if ("id".equalsIgnoreCase(attrName)) {
            LDAPObject ldapObject = ldapProvider.loadLDAPUserByUuid(realm, attrValue);
            ldapObjects = ldapObject == null ? Collections.emptyList() : Collections.singletonList(ldapObject);
        } else if ("dn".equalsIgnoreCase(attrName)) {
            LDAPObject ldapObject = ldapProvider.loadLDAPUserByDN(realm, LDAPDn.fromString(attrValue));
            ldapObjects = ldapObject == null ? Collections.emptyList() : Collections.singletonList(ldapObject);
        } else {
            try (LDAPQuery ldapQuery = LDAPUtils.createQueryForUserSearch(ldapProvider, realm)) {
                LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

                Condition attrCondition = conditionsBuilder.substring(attrName, null, new String[] { attrValue }, null);
                ldapQuery.addWhereCondition(attrCondition);

                ldapObjects = ldapQuery.getResultList();
            } catch (Exception e) {
                logger.errorf("LDAP substring search failed: %s", e.getMessage());
                throw new RuntimeException("LDAP substring search failed", e);
            }
        }

        logger.debugf("LDAP substring search for attribute '%s' with value containing '%s' returned %d results",
                attrName, attrValue, ldapObjects.size());

        return ldapObjects.stream();
    }

    /**
     * Search LDAP users by substring for a given attribute and return UserModel
     * stream.
     *
     * @param userProvider UserProvider instance
     * @param session      Keycloak session
     * @param realm        Realm model
     * @param attrName     LDAP attribute name
     * @param attrValue    Substring to search for
     * @return Stream of UserModel
     */
    public static Stream<UserModel> searchUserByAttributeSubstringStream(
            UserProvider userProvider,
            KeycloakSession session,
            RealmModel realm,
            String attrName,
            String attrValue) {
        List<ComponentModel> ldapComponents = realm.getStorageProviders(UserStorageProvider.class)
                .filter(c -> "ldap".equalsIgnoreCase(c.getProviderId()) && Boolean.parseBoolean(c.get("enabled")))
                .toList();

        logger.debugf("Found %d LDAP components in realm %s: %s",
                ldapComponents.size(),
                realm.getName(),
                ldapComponents.stream().map(ComponentModel::getProviderType).toList());

        return ldapComponents.stream()
                .flatMap(component -> {
                    ProviderFactory<UserStorageProvider> providerFactory = session
                            .getKeycloakSessionFactory()
                            .getProviderFactory(UserStorageProvider.class, component.getProviderId());
                    if (providerFactory instanceof UserStorageProviderFactory<?> genericFactory) {
                        Object created = genericFactory.create(session, component);

                        if (created instanceof LDAPStorageProvider ldapProvider) {
                            return searchLDAPBySubstring(ldapProvider, realm, attrName, attrValue)
                                    .map(ldapObj -> {
                                        String username = LDAPUtils.getUsername(
                                                ldapObj, ldapProvider.getLdapIdentityStore().getConfig());
                                        return userProvider.getUserByUsername(realm, username);
                                    })
                                    .filter(Objects::nonNull);
                        } else {
                            logger.warnf("Factory did not produce an LDAPStorageProvider for component: %s",
                                    component.getName());
                            return Stream.<UserModel>empty();
                        }
                    } else {
                        logger.warnf(
                                "Provider factory is not an instance of UserStorageProviderFactory for component: %s",
                                component.getName());
                        return Stream.<UserModel>empty();
                    }

                });

    }

}
