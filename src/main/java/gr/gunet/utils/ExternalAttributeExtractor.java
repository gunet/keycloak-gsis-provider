package gr.gunet.utils;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.core.type.TypeReference;

import org.jboss.logging.Logger;

import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.io.IOException;

public class ExternalAttributeExtractor {
    private static final Logger logger = Logger.getLogger(ExternalAttributeExtractor.class);

    /**
     * Extracts all occurrences of the given externalAttrName from the
     * BrokeredIdentityContext.
     * It checks flat attributes, flat contextData, and JSON structures within
     * contextData.
     * 
     * @param externalAttrName The name of the external attribute to extract
     * @param brokerContext    The BrokeredIdentityContext to extract from
     * @return Set of extracted attribute values
     */
    public static Set<String> extractValues(String externalAttrName, BrokeredIdentityContext brokerContext) {
        Set<String> foundValues = new LinkedHashSet<>();

        Object flatAttr = brokerContext.getUserAttribute(externalAttrName);
        if (flatAttr != null) {
            foundValues.addAll(asStringSet(flatAttr));
            logger.debugf("Found %s in brokerContext attributes: %s", externalAttrName, foundValues);
        }

        brokerContext.getContextData().forEach((key, val) -> {
            if (key.equalsIgnoreCase(externalAttrName) && val != null) {
                foundValues.add(String.valueOf(val));
                logger.debugf("Found %s directly in contextData[%s]: %s", externalAttrName, key, val);
            }
        });

        brokerContext.getContextData().forEach((key, val) -> {
            if (val == null)
                return;

            if (val instanceof String str && (str.trim().startsWith("{") || str.trim().startsWith("["))) {
                try {
                    Object parsed = JsonSerialization.readValue(str, Object.class);
                    extractFromObject(parsed, externalAttrName, foundValues);
                } catch (IOException e) {
                    logger.debugf("Failed to parse JSON for key '%s': %s", key, e.getMessage());
                }
            } else if (val instanceof Map<?, ?> || val instanceof List<?>) {
                extractFromObject(val, externalAttrName, foundValues);
            }
        });

        Object userInfoRaw = brokerContext.getContextData().get("UserInfo");
        if (userInfoRaw != null) {
            try {
                Map<String, Object> userInfo = JsonSerialization.readValue(userInfoRaw.toString(),
                        new TypeReference<Map<String, Object>>() {
                        });

                Object direct = userInfo.get(externalAttrName);
                if (direct != null)
                    foundValues.addAll(asStringSet(direct));

                Object attributes = userInfo.get("attributes");
                if (attributes instanceof Map<?, ?> attrsMap) {
                    extractFromObject(attrsMap, externalAttrName, foundValues);
                }

            } catch (Exception e) {
                logger.errorf(e, "Failed to parse UserInfo JSON for attribute '%s'", externalAttrName);
            }
        }

        if (foundValues.isEmpty()) {
            logger.debugf("No values found for external attribute '%s'", externalAttrName);
        }

        return foundValues;
    }

    /**
     * Extracts all key/value pairs (flattened) from the BrokeredIdentityContext.
     * Same principles as {@code extractValues()} but collects everything.
     * 
     * @param brokerContext The BrokeredIdentityContext to extract from
     * @return Map of attribute names to sets of values
     */
    public static Map<String, Set<String>> extractAll(BrokeredIdentityContext brokerContext) {
        Map<String, Set<String>> allValues = new LinkedHashMap<>();

        brokerContext.getAttributes().forEach((key, vals) -> {
            if (vals != null && !vals.isEmpty()) {
                allValues.computeIfAbsent(key, k -> new LinkedHashSet<>()).addAll(vals);
            }
        });

        brokerContext.getContextData().forEach((key, val) -> {
            extractAllFromObject(key, val, allValues);
        });

        Object userInfoRaw = brokerContext.getContextData().get("UserInfo");
        if (userInfoRaw != null) {
            try {
                Map<String, Object> userInfo = JsonSerialization.readValue(userInfoRaw.toString(),
                        new TypeReference<Map<String, Object>>() {
                        });
                userInfo.forEach((key, val) -> extractAllFromObject(key, val, allValues));
                Object attributes = userInfo.get("attributes");
                if (attributes instanceof Map<?, ?> attrsMap) {
                    attrsMap.forEach((key, val) -> extractAllFromObject(String.valueOf(key), val, allValues));
                }
            } catch (Exception e) {
                logger.errorf(e, "Failed to parse UserInfo JSON for extractAll");
            }
        }

        return allValues;
    }

    /**
     * Helper to extract all key/value pairs from an object into the provided map.
     * 
     * @param initialKey The initial key associated with the source object
     * @param source     The source object (Map, List, or String)
     * @param allValues  The map to collect all extracted key/value pairs
     */
    private static void extractAllFromObject(String initialKey, Object source,
            Map<String, Set<String>> allValues) {
        if (source == null)
            return;

        Deque<Map.Entry<String, Object>> stack = new ArrayDeque<>();
        stack.push(Map.entry(initialKey, source));

        while (!stack.isEmpty()) {
            Map.Entry<String, Object> current = stack.pop();
            String key = current.getKey();
            Object val = current.getValue();

            if (val == null)
                continue;

            if (val instanceof String str) {
                allValues.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(str);

                String trimmed = str.trim();
                if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                    try {
                        Object parsed = JsonSerialization.readValue(trimmed, Object.class);
                        stack.push(Map.entry(key, parsed));
                    } catch (IOException ignored) {
                    }
                }
            } else if (val instanceof Map<?, ?> map) {
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    String nestedKey = String.valueOf(entry.getKey());
                    stack.push(Map.entry(nestedKey, entry.getValue()));
                }
            } else if (val instanceof Collection<?> coll) {
                for (Object element : coll) {
                    stack.push(Map.entry(key, element));
                }
            } else {
                allValues.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(String.valueOf(val));
            }
        }
    }

    /**
     * Extract values from nested Maps, Lists and JSON.
     * 
     * @param source      The source object (Map, List, or String)
     * @param keyToFind   The key to search for (case-insensitive)
     * @param foundValues The set to collect found values
     */
    private static void extractFromObject(Object source, String keyToFind, Set<String> foundValues) {
        if (source == null)
            return;

        Deque<Object> stack = new ArrayDeque<>();
        stack.push(source);

        while (!stack.isEmpty()) {
            Object current = stack.pop();

            if (current instanceof Map<?, ?> map) {
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    Object key = entry.getKey();
                    Object value = entry.getValue();

                    if (key != null && keyToFind.equalsIgnoreCase(String.valueOf(key)) && value != null) {
                        foundValues.addAll(asStringSet(value));
                    }

                    if (value instanceof Map<?, ?> || value instanceof List<?> || value instanceof String) {
                        stack.push(value);
                    }
                }
            } else if (current instanceof List<?> list) {
                for (Object element : list) {
                    if (element != null) {
                        stack.push(element);
                    }
                }
            } else if (current instanceof String str) {
                String trimmed = str.trim();
                if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                    try {
                        Object parsed = JsonSerialization.readValue(trimmed, Object.class);
                        stack.push(parsed);
                    } catch (IOException e) {
                        logger.debugf("Failed to create JSON from string: %s", e.getMessage());
                    }
                }
            }
        }
    }

    /**
     * Utility to normalize different value types into String sets.
     * 
     * @param val The input value (Collection, Array, or single Object)
     * @return Set of String representations
     */
    private static Set<String> asStringSet(Object val) {
        Set<String> result = new LinkedHashSet<>();
        if (val instanceof Collection<?> coll) {
            for (Object v : coll)
                result.add(String.valueOf(v));
        } else if (val.getClass().isArray()) {
            for (Object v : (Object[]) val)
                result.add(String.valueOf(v));
        } else {
            result.add(String.valueOf(val));
        }
        return result;
    }
}
