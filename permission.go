package permission

import (
	"errors"
	"strings"
)

var (
	ErrInvalidSyntax = errors.New("permission: Invalid Syntax")
)

type Permission struct {
	Allow       bool
	Permissions []string
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
	}() + ":" + strings.Join(p.Permissions, ":")
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
	p.Permissions = perm.Permissions

	return nil
}

func FromString(s string) (Permission, error) {
	p := Permission{Allow: true}

	split := strings.Split(s, ":")

	if split[0] == "-" {
		p.Allow = false
	}

	if split[0] == "+" || split[0] == "-" {
		p.Permissions = split[1:]
	} else {
		p.Permissions = split
	}

	for _, v := range p.Permissions {
		if v == "" {
			return Permission{}, ErrInvalidSyntax
		}
	}

	return p, nil
}

func (p Permission) HasPermission(target Permission) bool {
	return p.Allow && target.Allow && func() bool {
		if len(p.Permissions) > len(target.Permissions) {
			return false
		}

		for i, v := range p.Permissions {
			if v == "*" {
				continue
			}
			if v != target.Permissions[i] {
				return false
			}
		}

		return true
	}()
}
