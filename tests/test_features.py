import unittest

from urlshield.features import FEATURE_COLUMNS, extract_features, feature_dict, validate_url_input


class FeatureExtractorTests(unittest.TestCase):
    def test_exact_feature_order_and_length(self):
        values = extract_features("https://example.com/")
        self.assertEqual(len(FEATURE_COLUMNS), 23)
        self.assertEqual(len(values), 23)
        self.assertEqual(list(feature_dict("https://example.com/")), FEATURE_COLUMNS)

    def test_strip_and_remove_www_before_counting(self):
        actual = feature_dict("  https://www.example.com/login  ")
        expected = feature_dict("https://example.com/login")
        self.assertEqual(actual, expected)
        self.assertEqual(actual["."], 1)
        self.assertEqual(actual["suspicious_word_count"], 1)

    def test_counts_raw_ip_and_url_characters(self):
        actual = feature_dict("http://192.0.2.1/a?x=1@host")
        self.assertEqual(actual["having_ip_address"], 1)
        self.assertEqual(actual["@"] , 1)
        self.assertEqual(actual["https"], 0)
        self.assertEqual(actual["query_length"], len("x=1@host"))

    def test_non_http_scheme_is_rejected(self):
        valid, reason = validate_url_input("javascript:alert(1)")
        self.assertFalse(valid)
        self.assertIn("HTTP and HTTPS", reason)

    def test_empty_and_oversized_urls_are_rejected(self):
        self.assertFalse(validate_url_input("   ")[0])
        self.assertFalse(validate_url_input("https://example.com/" + "a" * 20, max_length=10)[0])

    def test_malformed_authority_does_not_raise(self):
        self.assertFalse(validate_url_input("http://[broken")[0])
        self.assertFalse(validate_url_input("https://example.com:99999")[0])
        self.assertTrue(validate_url_input("example.com:8080/path")[0])


if __name__ == "__main__":
    unittest.main()
