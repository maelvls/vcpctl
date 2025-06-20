package main

import "testing"

func Test_removeANSI(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"\x1b[1;34mHello\x1b[0m", "Hello"},
		{"\x1b[1;34mHello\x1b[0m \x1b[1;34mWorld\x1b[0m", "Hello World"},
		{"\x1b[38;5;1m", ""},
		{"\x1b[1;31m", ""},
		{"\x1b[90m", ""},
		{"\x1b[1;34m", ""},
		{"\x1b[0m", ""},
		{"\x1b[38;5;34m foobar \x1b[0m", " foobar "},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := withoutANSI(test.input)
			if result != test.expected {
				t.Errorf("Expected %q but got %q", test.expected, result)
			}
		})
	}
}
