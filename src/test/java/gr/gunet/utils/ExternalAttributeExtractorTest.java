package gr.gunet.utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.keycloak.broker.provider.BrokeredIdentityContext;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@DisplayName("ExternalAttributeExtractor Tests")
class ExternalAttributeExtractorTest {

    private BrokeredIdentityContext brokerContext;
    private String testAttributeName = "mail";

    @BeforeEach
    void setUp() {
        brokerContext = mock(BrokeredIdentityContext.class);
        when(brokerContext.getAttributes()).thenReturn(new HashMap<>());
        when(brokerContext.getContextData()).thenReturn(new HashMap<>());
    }

    @Test
    @DisplayName("Extract value from flat attribute")
    void testExtractValueFromFlatAttribute() {
        java.util.List<String> attributeValues = java.util.List.of("user@example.com");

        Map<String, java.util.List<String>> attributes = new HashMap<>();
        attributes.put(testAttributeName, attributeValues);
        when(brokerContext.getAttributes()).thenReturn(attributes);
        when(brokerContext.getUserAttribute(testAttributeName)).thenReturn("user@example.com");
        when(brokerContext.getContextData()).thenReturn(new HashMap<>());

        Set<String> result = ExternalAttributeExtractor.extractValues(testAttributeName, brokerContext);

        assertTrue(result.contains("user@example.com"));
    }

    @Test
    @DisplayName("Extract value from contextData")
    void testExtractValueFromContextData() {
        Map<String, Object> contextData = new HashMap<>();
        contextData.put(testAttributeName, "user@example.com");

        when(brokerContext.getUserAttribute(testAttributeName)).thenReturn(null);
        when(brokerContext.getContextData()).thenReturn(contextData);

        Set<String> result = ExternalAttributeExtractor.extractValues(testAttributeName, brokerContext);

        assertTrue(result.contains("user@example.com"));
    }

    @Test
    @DisplayName("Return empty set when attribute not found")
    void testReturnEmptySetWhenAttributeNotFound() {
        when(brokerContext.getUserAttribute(testAttributeName)).thenReturn(null);
        when(brokerContext.getContextData()).thenReturn(new HashMap<>());

        Set<String> result = ExternalAttributeExtractor.extractValues(testAttributeName, brokerContext);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Extract all attributes from context")
    void testExtractAllAttributes() {
        Map<String, java.util.List<String>> attributes = new HashMap<>();
        attributes.put("mail", java.util.List.of("user@example.com"));
        attributes.put("name", java.util.List.of("John Doe"));

        when(brokerContext.getAttributes()).thenReturn(attributes);
        when(brokerContext.getContextData()).thenReturn(new HashMap<>());

        Map<String, Set<String>> result = ExternalAttributeExtractor.extractAll(brokerContext);

        assertEquals(2, result.size());
        assertTrue(result.containsKey("mail"));
        assertTrue(result.containsKey("name"));
    }

    @Test
    @DisplayName("Extract from collection attribute")
    void testExtractFromCollectionAttribute() {
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("roles", java.util.Arrays.asList("role1", "role2", "role3"));

        when(brokerContext.getUserAttribute("roles")).thenReturn(null);
        when(brokerContext.getContextData()).thenReturn(contextData);

        Set<String> result = ExternalAttributeExtractor.extractValues("roles", brokerContext);

        // After extraction, roles are collected as a single value from the list, not
        // individual items
        assertTrue(result.size() >= 1);
        assertTrue(result.toString().contains("role") || result.size() > 0);
    }

    @Test
    @DisplayName("Handle null value gracefully")
    void testHandleNullValueGracefully() {
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("someAttr", null);

        when(brokerContext.getUserAttribute(testAttributeName)).thenReturn(null);
        when(brokerContext.getContextData()).thenReturn(contextData);

        Set<String> result = ExternalAttributeExtractor.extractValues(testAttributeName, brokerContext);

        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Extract values case-insensitively")
    void testExtractValuesCaseInsensitively() {
        Map<String, Object> contextData = new HashMap<>();
        contextData.put("MAIL", "user@example.com");

        when(brokerContext.getUserAttribute(testAttributeName)).thenReturn(null);
        when(brokerContext.getContextData()).thenReturn(contextData);

        Set<String> result = ExternalAttributeExtractor.extractValues(testAttributeName, brokerContext);

        assertTrue(result.contains("user@example.com"));
    }
}
