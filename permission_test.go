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

func TestPermission_HasPermission(t *testing.T) {
	for i, v := range []struct {
		sPerm Permission
		uPerm Permission
		has   bool
	}{
		{mustFromString("hello"), mustFromString("hello"), true},
		{mustFromString("hello"), mustFromString("world"), false},
		{mustFromString("-:hello"), mustFromString("hello"), false},
		{mustFromString("hello"), mustFromString("-:hello"), false},
		{mustFromString("hello:world"), mustFromString("hello:world"), true},
		{mustFromString("hello:world"), mustFromString("hello:*"), true},
		{mustFromString("hello:world"), mustFromString("*"), true},
		{mustFromString("hello:world"), mustFromString("-:*"), false},
		{mustFromString("hello:world:foo"), mustFromString("hello:*:foo"), true},
		{mustFromString("hello:bar:foo"), mustFromString("hello:*:foo"), true},
		{mustFromString("hello:bar:foo"), mustFromString("hello:*:bar"), false},
		{mustFromString("hello"), mustFromString("hello:world"), false},
		{mustFromString("hello"), mustFromString("hello:*"), false},
	} {
		if v.uPerm.HasPermission(v.sPerm) != v.has {
			t.Errorf("%d: Validation Error: %t(target) != %t(result)", i, v.has, v.uPerm.HasPermission(v.sPerm))
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
