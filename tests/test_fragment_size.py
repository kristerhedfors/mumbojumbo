#!/usr/bin/env python3
"""Tests for fragment size calculation function."""

import pytest
from mumbojumbo import calculate_safe_max_fragment_data_len


class TestFragmentSizeCalculation:
    """Test the simplified fragment size calculation formula."""

    def test_formula_short_domains(self):
        """Test formula correctness for short domains (3-12 chars)."""
        # Formula: 83 - len(domain) // 3

        # 3 chars: 83 - 1 = 82
        assert calculate_safe_max_fragment_data_len('.xy') == 82

        # 6 chars: 83 - 2 = 81
        assert calculate_safe_max_fragment_data_len('.ab.xy') == 81

        # 8 chars: 83 - 2 = 81
        assert calculate_safe_max_fragment_data_len('.asd.qwe') == 81

        # 9 chars: 83 - 3 = 80
        assert calculate_safe_max_fragment_data_len('.test.com') == 80

        # 12 chars: 83 - 4 = 79
        assert calculate_safe_max_fragment_data_len('.example.com') == 79

    def test_formula_medium_domains(self):
        """Test formula for medium-length domains (13-22 chars)."""
        # 15 chars: 83 - 5 = 78
        assert calculate_safe_max_fragment_data_len('.somedomain.com') == 78

        # 18 chars: 83 - 6 = 77
        assert calculate_safe_max_fragment_data_len('.longerexample.com') == 77

        # 22 chars: 83 - 7 = 76
        assert calculate_safe_max_fragment_data_len('.verylongdomain.example') == 76

    def test_formula_long_domains(self):
        """Test formula for long domains (23-33 chars)."""
        # 26 chars: 83 - 8 = 75
        assert calculate_safe_max_fragment_data_len('.extremely-long-domain.com') == 75

        # 30 chars: 83 - 10 = 73
        assert calculate_safe_max_fragment_data_len('.this-is-a-very-long-domain.io') == 73

        # 33 chars: 83 - 11 = 72
        assert calculate_safe_max_fragment_data_len('.super-extremely-long-subdomain.x') == 72

    def test_edge_case_empty_domain(self):
        """Test with empty domain string."""
        # 0 chars: 83 - 0 = 83
        assert calculate_safe_max_fragment_data_len('') == 83

    def test_edge_case_single_char(self):
        """Test with single character domain."""
        # 1 char: 83 - 0 = 83
        assert calculate_safe_max_fragment_data_len('.') == 83

    def test_edge_case_max_length_domain(self):
        """Test with maximum allowed domain length (143 chars)."""
        # 143 chars: 83 - 47 = 36
        long_domain = '.' + 'x' * 142
        assert calculate_safe_max_fragment_data_len(long_domain) == 36

    def test_error_domain_too_long(self):
        """Test that domains > 143 chars raise ValueError."""
        # 144 chars should fail
        too_long = '.' + 'x' * 143
        with pytest.raises(ValueError, match='Domain too long'):
            calculate_safe_max_fragment_data_len(too_long)

        # 200 chars should also fail
        way_too_long = '.' + 'x' * 199
        with pytest.raises(ValueError, match='Domain too long'):
            calculate_safe_max_fragment_data_len(way_too_long)

    def test_integer_division_behavior(self):
        """Test that integer division works correctly for various lengths."""
        # Verify integer division behavior
        # len=0: 0//3=0
        # len=1: 1//3=0
        # len=2: 2//3=0
        # len=3: 3//3=1
        # len=4: 4//3=1
        # len=5: 5//3=1
        # len=6: 6//3=2

        assert calculate_safe_max_fragment_data_len('') == 83      # 0//3=0, 83-0=83
        assert calculate_safe_max_fragment_data_len('x') == 83     # 1//3=0, 83-0=83
        assert calculate_safe_max_fragment_data_len('xx') == 83    # 2//3=0, 83-0=83
        assert calculate_safe_max_fragment_data_len('xxx') == 82   # 3//3=1, 83-1=82
        assert calculate_safe_max_fragment_data_len('xxxx') == 82  # 4//3=1, 83-1=82
        assert calculate_safe_max_fragment_data_len('xxxxx') == 82 # 5//3=1, 83-1=82
        assert calculate_safe_max_fragment_data_len('xxxxxx') == 81 # 6//3=2, 83-2=81

    def test_realistic_domains(self):
        """Test with realistic domain examples."""
        # Common TLDs and patterns
        assert calculate_safe_max_fragment_data_len('.com') == 82  # len=4, 4//3=1, 83-1=82
        assert calculate_safe_max_fragment_data_len('.org') == 82  # len=4, 4//3=1, 83-1=82
        assert calculate_safe_max_fragment_data_len('.net') == 82  # len=4, 4//3=1, 83-1=82
        assert calculate_safe_max_fragment_data_len('.io') == 82   # len=3, 3//3=1, 83-1=82

        # Subdomains
        assert calculate_safe_max_fragment_data_len('.api.example.com') == 78      # len=16, 16//3=5, 83-5=78
        assert calculate_safe_max_fragment_data_len('.staging.myapp.io') == 78     # len=17, 17//3=5, 83-5=78
        assert calculate_safe_max_fragment_data_len('.prod.internal.corp') == 77   # len=19, 19//3=6, 83-6=77
