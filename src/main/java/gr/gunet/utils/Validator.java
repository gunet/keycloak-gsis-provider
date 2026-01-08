package gr.gunet.utils;

import org.apache.commons.text.similarity.LevenshteinDistance;
import java.text.Normalizer;

public class Validator {

    // LevenshteinDistance instance in order to avoid repeated creation of objects.
    // Also avoids deprecation warnings.
    private static final LevenshteinDistance LD = LevenshteinDistance.getDefaultInstance();

    /**
     * Validates a Greek TIN (Tax Identification Number).
     * 
     * @param tin The 9-digit TIN string
     * @return true if valid, false otherwise
     */
    public static boolean checkTin(String tin) {
        tin = normalizeTin(tin);

        // Must be exactly 9 digits
        if (tin == null || !tin.matches("\\d{9}")) {
            return false;
        }

        int checksum = 0;

        // Iterate over the first 8 digits
        for (int i = 0; i < 8; i++) {
            int n = Character.getNumericValue(tin.charAt(i));
            checksum += n * (int) Math.pow(2, 8 - i);
        }

        // Calculate check digit
        int checkDigit = (checksum % 11) % 10;

        // Compare with the last digit
        int lastDigit = Character.getNumericValue(tin.charAt(8));

        return checkDigit == lastDigit;
    }

    /**
     * Normalizes a Greek TIN by trimming spaces, removing extra spaces,
     * and stripping leading "00" if present in 11-digit TINs.
     *
     * @param tin The input TIN string
     * @return The normalized TIN string
     */
    public static String normalizeTin(String tin) {
        if (tin == null) {
            return null;
        }
        tin = normalizeString(tin);
        // If it's 11 digits and starts with "00", strip the first two digits
        if (tin.matches("\\d{11}") && tin.startsWith("00")) {
            tin = tin.substring(2);
        }

        return tin;
    }

    /**
     * Normalizes a String by trimming spaces and removing extra spaces.
     *
     * @param value The input string
     * @return The normalized string
     */
    public static String normalizeString(String value) {
        if (value == null) {
            return null;
        }

        // Trim any leading/trailing whitespace
        value = value.trim();

        // Remove spaces inside the string
        value = value.replaceAll("\\s+", "");

        return value;
    }

    /**
     * Normalizes visually confusable Latin uppercase letters that resemble
     * Greek capital characters, addressing common data-entry errors to
     * minimize false mismatches during surname normalization and comparison.
     * 
     * @param s The input string
     * @return The string with Latin look-alike letters replaced by Greek ones
     */
    private static String latinToGreekLookalikes(String s) {
        return s
                .replace('A', 'Α').replace('B', 'Β').replace('E', 'Ε')
                .replace('H', 'Η').replace('I', 'Ι').replace('K', 'Κ')
                .replace('M', 'Μ').replace('N', 'Ν').replace('O', 'Ο')
                .replace('P', 'Ρ').replace('T', 'Τ').replace('X', 'Χ')
                .replace('Y', 'Υ');
    }

    /**
     * Normalizes Greek surnames for consistent comparison
     * 
     * @param input The input surname
     * @return The normalized surname
     */
    public static String normalizeGreek(String input) {
        if (input == null)
            return "";

        // Fix Latin look-alike letters
        String s = latinToGreekLookalikes(input);

        // Convert to lowercase
        s = s.toLowerCase();

        // Replace final sigma (ς) with standard sigma (σ) to unify forms.
        // This step may be redundant if a Levenshtein threshold (≤ 1) is applied.
        s = s.replace('ς', 'σ');

        // Unicode NFD decomposition and diacritic removal
        s = Normalizer.normalize(s, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "") // Remove diacritical marks
                .replaceAll("[^\\p{InGreek}\\s]", " ") // Keep only Greek letters and spaces
                .replaceAll("\\s+", " ") // Collapse multiple spaces
                .trim();

        return s;
    }

    /**
     * Computes the Levenshtein distance between normalized surnames
     * Because of the normalization the expected distance should be
     * 0 (exact match) or at most 1, accounting for minor spelling
     * or transcription variations.
     * 
     * @param a First surname
     * @param b Second surname
     * @return Levenshtein distance between normalized surnames
     */
    public static int levenshteinDistance(String a, String b) {
        return LD.apply(normalizeGreek(a), normalizeGreek(b));
    }
}
