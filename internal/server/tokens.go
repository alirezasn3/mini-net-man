package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

const maxTokens = 20

func (s *Server) tokenList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, orEmpty(s.eng.Config().Web.Tokens))
}

// tokenCreate makes a token and returns its secret once; only a hash is kept.
// Like a username change it asks for the password again.
func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		ReadOnly bool   `json:"read_only"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if !checkPassword(s.eng.Config().Web.Users, userOf(r), in.Password) {
		httpErr(w, http.StatusForbidden, errors.New("password is wrong"))
		return
	}
	if name == "" || len(name) > 48 {
		httpErr(w, http.StatusBadRequest, errors.New("give the token a name of 1 to 48 characters, such as the program that will use it"))
		return
	}
	secret := newToken()
	tok := model.Token{ID: engine.NewID(), Name: name, Hash: hashToken(secret), Prefix: secret[:len(tokenPrefix)+8],
		ReadOnly: in.ReadOnly, Created: time.Now().UTC().Format(time.RFC3339)}
	_, err := s.eng.Update(func(c *model.Config) error {
		if len(c.Web.Tokens) >= maxTokens {
			return fmt.Errorf("at most %d tokens; delete one you no longer use", maxTokens)
		}
		for _, t := range c.Web.Tokens {
			if strings.EqualFold(t.Name, name) {
				return fmt.Errorf("there is already a token called %q", name)
			}
		}
		c.Web.Tokens = append(c.Web.Tokens, tok)
		return nil
	})
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]any{"token": secret, "id": tok.ID, "name": tok.Name, "prefix": tok.Prefix, "read_only": tok.ReadOnly, "created": tok.Created})
}

func (s *Server) tokenDelete(w http.ResponseWriter, r *http.Request) {
	want := r.PathValue("id")
	s.mutate(w, func(c *model.Config) error {
		for i, t := range c.Web.Tokens {
			if t.ID == want {
				c.Web.Tokens = append(c.Web.Tokens[:i], c.Web.Tokens[i+1:]...)
				return nil
			}
		}
		return errNotFound
	})
}
