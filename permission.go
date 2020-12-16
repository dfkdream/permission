package permission

import (
	"errors"
	"strings"
)

var (
	ErrInvalidSyntax = errors.New("permission: Invalid Syntax")
)

type Permission struct {
	Allow      bool
	Namespaces []string
}

func (p Permission) Equals(target Permission) bool {
	return p.String() == target.String()
}

func (p Permission) String() string {
	return func() string {
		if p.Allow {
			return "+"
		}
		return "-"
	}() + ":" + strings.Join(p.Namespaces, ":")
}

func (p Permission) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p *Permission) UnmarshalText(b []byte) error {
	perm, err := FromString(string(b))
	if err != nil {
		return err
	}

	p.Allow = perm.Allow
	p.Namespaces = perm.Namespaces

	return nil
}

func FromString(s string) (Permission, error) {
	p := Permission{Allow: true}

	split := strings.Split(s, ":")

	if split[0] == "-" {
		p.Allow = false
	}

	if split[0] == "+" || split[0] == "-" {
		p.Namespaces = split[1:]
	} else {
		p.Namespaces = split
	}

	for _, v := range p.Namespaces {
		if v == "" {
			return Permission{}, ErrInvalidSyntax
		}
	}

	return p, nil
}

func (p Permission) HasPermission(target Permission) bool {
	return p.Allow && target.Allow && func() bool {
		if len(p.Namespaces) > len(target.Namespaces) {
			return false
		}

		for i, v := range p.Namespaces {
			if v == "*" {
				continue
			}
			if v != target.Namespaces[i] {
				return false
			}
		}

		return true
	}()
}
