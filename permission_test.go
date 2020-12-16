package permission

import (
	"bytes"
	"encoding/json"
	"log"
	"testing"
)

func TestPermission_String(t *testing.T) {
	for i, v := range []struct {
		p Permission
		s string
	}{
		{p: Permission{Allow: true, Namespaces: []string{"hello", "world"}}, s: "+:hello:world"},
		{p: Permission{Allow: true, Namespaces: []string{"*"}}, s: "+:*"},
		{p: Permission{Allow: false, Namespaces: []string{"hello", "world"}}, s: "-:hello:world"},
		{p: Permission{Allow: false, Namespaces: []string{"*"}}, s: "-:*"},
	} {
		if v.p.String() != v.s {
			t.Errorf("%d: Result not equals: %s(target) != %s(result)", i, v.s, v.p.String())
		}
	}
}

func TestFromString(t *testing.T) {
	for i, v := range []struct {
		str  string
		perm Permission
		err  error
	}{
		{"hello:world", Permission{true, []string{"hello", "world"}}, nil},
		{"+:hello:world", Permission{true, []string{"hello", "world"}}, nil},
		{"+hello:world", Permission{true, []string{"+hello", "world"}}, nil},
		{"-:hello:world", Permission{false, []string{"hello", "world"}}, nil},
		{"-hello:world", Permission{true, []string{"-hello", "world"}}, nil},
		{"hello:*", Permission{true, []string{"hello", "*"}}, nil},
		{"*", Permission{true, []string{"*"}}, nil},
		{"-:*", Permission{false, []string{"*"}}, nil},
		{":world", Permission{}, ErrInvalidSyntax},
		{"hello::world", Permission{}, ErrInvalidSyntax},
		{"", Permission{}, ErrInvalidSyntax},
	} {
		perm, err := FromString(v.str)
		if err != v.err {
			t.Errorf("%d: Error Mismatch: %s(target) != %s(result)", i, v.err, err)
		}

		if v.err != nil {
			continue
		}

		if !v.perm.Equals(perm) {
			t.Errorf("%d: Permission Parse Error: %s(target) != %s(result)", i, v.perm, perm)
		}
	}
}

func mustFromString(p string) Permission {
	perm, err := FromString(p)
	if err != nil {
		log.Fatal(err)
	}
	return perm
}

func TestPermission_MatchNamespace(t *testing.T) {
	for i, v := range []struct {
		sPerm Permission
		uPerm Permission
		has   bool
	}{
		{mustFromString("a:c"), mustFromString("*"), true},
		{mustFromString("a:c"), mustFromString("*:*"), true},
		{mustFromString("a:c"), mustFromString("*:c"), true},
		{mustFromString("a:c"), mustFromString("*:d"), false},
		{mustFromString("a:c"), mustFromString("a:*"), true},
		{mustFromString("a:c"), mustFromString("a:c"), true},
		{mustFromString("a:c"), mustFromString("a:d"), false},
		{mustFromString("a:c"), mustFromString("b"), false},
		{mustFromString("a:d"), mustFromString("*"), true},
		{mustFromString("a:d"), mustFromString("*:*"), true},
		{mustFromString("a:d"), mustFromString("*:c"), false},
		{mustFromString("a:d"), mustFromString("*:d"), true},
		{mustFromString("a:d"), mustFromString("a:*"), true},
		{mustFromString("a:d"), mustFromString("a:c"), false},
		{mustFromString("a:d"), mustFromString("a:d"), true},
		{mustFromString("a:d"), mustFromString("b"), false},
		{mustFromString("b"), mustFromString("*"), true},
		{mustFromString("b"), mustFromString("*:*"), false},
		{mustFromString("b"), mustFromString("*:c"), false},
		{mustFromString("b"), mustFromString("*:d"), false},
		{mustFromString("b"), mustFromString("a:*"), false},
		{mustFromString("b"), mustFromString("a:c"), false},
		{mustFromString("b"), mustFromString("a:d"), false},
		{mustFromString("b"), mustFromString("b"), true},
	} {
		if v.uPerm.MatchNamespace(v.sPerm) != v.has {
			t.Errorf("%d: Validation Error: %t(target) != %t(result)", i, v.has, v.uPerm.MatchNamespace(v.sPerm))
		}
	}
}

func TestPermission_MarshalText(t *testing.T) {
	for i, v := range []struct {
		p Permission
		s []byte
	}{
		{p: Permission{Allow: true, Namespaces: []string{"hello", "world"}}, s: []byte(`"+:hello:world"`)},
		{p: Permission{Allow: true, Namespaces: []string{"*"}}, s: []byte(`"+:*"`)},
		{p: Permission{Allow: false, Namespaces: []string{"hello", "world"}}, s: []byte(`"-:hello:world"`)},
		{p: Permission{Allow: false, Namespaces: []string{"*"}}, s: []byte(`"-:*"`)},
	} {
		res, err := json.Marshal(v.p)
		if err != nil {
			t.Error(err)
			continue
		}

		if !bytes.Equal(res, v.s) {
			t.Errorf("%d: Result not equals: %s(target) != %s(result)", i, v.s, res)
		}
	}
}

func TestPermission_UnmarshalText(t *testing.T) {
	for i, v := range []struct {
		p Permission
		s []byte
		e error
	}{
		{p: Permission{Allow: true, Namespaces: []string{"hello", "world"}}, s: []byte(`"+:hello:world"`)},
		{p: Permission{Allow: true, Namespaces: []string{"*"}}, s: []byte(`"+:*"`)},
		{p: Permission{Allow: false, Namespaces: []string{"hello", "world"}}, s: []byte(`"-:hello:world"`)},
		{p: Permission{Allow: false, Namespaces: []string{"*"}}, s: []byte(`"-:*"`)},
		{p: Permission{Allow: false, Namespaces: []string{"*"}}, s: []byte(`""`), e: ErrInvalidSyntax},
	} {
		var res Permission
		err := json.Unmarshal(v.s, &res)

		if v.e != err {
			t.Errorf("%d: Error Mismatch: %s(target) != %s(result)", i, v.e, err)
		}

		if v.e != nil {
			continue
		}

		if !v.p.Equals(res) {
			t.Errorf("%d: Result not equals: %s(target) != %s(result)", i, v.s, res)
		}
	}
}

func TestPermission_HasPermission(t *testing.T) {
	p1 := []Permission{
		mustFromString("-:a:c:f:h:e"),
		mustFromString("+:a:c:f"),
		mustFromString("-:a:c:*:h"),
		mustFromString("+:a:c:*:*:d"),
		mustFromString("+:a:b:d"),
	}

	for i, v := range []struct {
		p   Permission
		u   []Permission
		has bool
	}{
		{mustFromString("a:c:f:g:d"), p1, true},
		{mustFromString("a:c:f:g:e"), p1, true},
		{mustFromString("a:c:f:h:d"), p1, true},
		{mustFromString("a:c:f:h:e"), p1, false},
		{mustFromString("a:c:i:g:d"), p1, true},
		{mustFromString("a:c:i:g:e"), p1, false},
		{mustFromString("a:c:i:h:d"), p1, false},
		{mustFromString("a:c:i:h:e"), p1, false},
		{mustFromString("a:b:d"), p1, true},
		{mustFromString("a:b:e"), p1, false},
	} {
		if r := v.p.HasPermission(v.u); r != v.has {
			t.Errorf("%d: Result not equals: %t(target) != %t(result)", i, v.has, r)
		}
	}
}
