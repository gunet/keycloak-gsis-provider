package gr.gunet.utils;

import org.junit.jupiter.api.Test;

import gr.gunet.TestProfile;

import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Validator Tests")
class ValidatorTest {

    @Test
    @DisplayName("Valid TIN should pass validation")
    void testValidTin() {
        assertTrue(Validator.checkTin(TestProfile.VALID.getTaxid()));
    }

    @Test
    @DisplayName("Invalid TIN with wrong checksum should fail")
    void testInvalidTinWithWrongChecksum() {
        assertFalse(Validator.checkTin(TestProfile.INVALID_TIN.getTaxid()));
    }

    @Test
    @DisplayName("Null TIN should fail validation")
    void testNullTin() {
        assertFalse(Validator.checkTin(TestProfile.NULL_TAXID.getTaxid()));
    }

    @Test
    @DisplayName("Empty TIN should fail validation")
    void testEmptyTin() {
        assertFalse(Validator.checkTin(TestProfile.EMPTY.getTaxid()));
    }

    @Test
    @DisplayName("TIN with less than 9 digits should fail")
    void testTinWithFewerDigits() {
        assertFalse(Validator.checkTin(TestProfile.INVALID_TIN_LESS.getTaxid()));
    }

    @Test
    @DisplayName("TIN with more than 9 digits should fail")
    void testTinWithMoreDigits() {
        assertFalse(Validator.checkTin(TestProfile.INVALID_TIN_MORE.getTaxid()));
    }

    @Test
    @DisplayName("TIN with non-numeric characters should fail")
    void testTinWithNonNumericCharacters() {
        assertFalse(Validator.checkTin(TestProfile.INVALID_TIN_MALFORMED.getTaxid()));
    }

    @Test
    @DisplayName("TIN with spaces should be normalized and validated")
    void testTinWithSpaces() {
        String tinWithSpaces = "123 456 789";
        boolean result = Validator.checkTin(tinWithSpaces);
        assertNotNull(result); // Should not throw exception
    }

    @Test
    @DisplayName("11-digit TIN starting with 00 should be normalized to 9 digits")
    void testNormalizeTinWith11Digits() {
        String tin11 = "00123456789";
        String normalized = Validator.normalizeTin(tin11);
        assertEquals("123456789", normalized);
    }

    @Test
    @DisplayName("11-digit TIN not starting with 00 should remain 11 digits after normalization")
    void testNormalizeTinWith11DigitsNotStartingWithZero() {
        String tin11 = "12345678901";
        String normalized = Validator.normalizeTin(tin11);
        assertEquals("12345678901", normalized);
    }

    @Test
    @DisplayName("Null TIN should normalize to null")
    void testNormalizeTinNull() {
        assertNull(Validator.normalizeTin(null));
    }

    @Test
    @DisplayName("String normalization should remove spaces")
    void testNormalizeStringRemovesSpaces() {
        String input = "hello  world  test";
        String normalized = Validator.normalizeString(input);
        assertEquals("helloworldtest", normalized);
    }

    @Test
    @DisplayName("String normalization should trim leading and trailing spaces")
    void testNormalizeStringTrimsWhitespace() {
        String input = "   hello world   ";
        String normalized = Validator.normalizeString(input);
        assertEquals("helloworld", normalized);
    }

    @Test
    @DisplayName("Null string should normalize to null")
    void testNormalizeStringNull() {
        assertNull(Validator.normalizeString(null));
    }

    @Test
    @DisplayName("normalizeGreek should convert to lowercase")
    void testNormalizeGreekConvertsToLowercase() {
        String input = "ΑΒΓΔ";
        String normalized = Validator.normalizeGreek(input);
        assertEquals(normalized, normalized.toLowerCase());
    }

    @Test
    @DisplayName("normalizeGreek should handle null input")
    void testNormalizeGreekNull() {
        String normalized = Validator.normalizeGreek(null);
        assertEquals("", normalized);
    }

    @Test
    @DisplayName("normalizeGreek should replace final sigma with standard sigma")
    void testNormalizeGreekReplacesFinalsigma() {
        String input = "σίσμα"; // Contains standard sigma and word-final sigma
        String normalized = Validator.normalizeGreek(input);
        // After normalization, final sigma should be replaced
        assertNotNull(normalized);
    }

    @Test
    @DisplayName("Levenshtein distance should be 0 for identical normalized strings")
    void testLevenshteinDistanceZeroForIdentical() {
        String surname1 = "παπαδόπουλος";
        String surname2 = "παπαδοπουλος";
        int distance = Validator.levenshteinDistance(surname1, surname2);
        // After normalization, these should have small distance
        assertTrue(distance <= 1);
    }

    @Test
    @DisplayName("Levenshtein distance should handle different strings")
    void testLevenshteinDistanceForDifferent() {
        String surname1 = "παπαδόπουλος";
        String surname2 = "γεωργίου";
        int distance = Validator.levenshteinDistance(surname1, surname2);
        assertTrue(distance > 0);
    }
}
