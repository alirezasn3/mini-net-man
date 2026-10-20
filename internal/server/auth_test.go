package server

import "testing"

func TestAllowed(t *testing.T) {
	cases := []struct {
		list []string
		ip   string
		want bool
	}{
		{nil, "127.0.0.1", true},
		{nil, "::1", true},
		{nil, "203.0.113.7", false}, // empty list never opens the panel up
		{[]string{"203.0.113.7"}, "203.0.113.7", true},
		{[]string{"203.0.113.7"}, "203.0.113.8", false},
		{[]string{"198.51.100.0/24"}, "198.51.100.200", true},
		{[]string{"198.51.100.0/24"}, "198.51.101.1", false},
		{[]string{"127.0.0.1"}, "not-an-ip", false},
	}
	for _, c := range cases {
		if got := allowed(c.list, c.ip); got != c.want {
			t.Errorf("allowed(%v, %q) = %v, want %v", c.list, c.ip, got, c.want)
		}
	}
}
