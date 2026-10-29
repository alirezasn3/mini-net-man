package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/alirezasn3/mini-net-man/internal/engine"
	"github.com/alirezasn3/mini-net-man/internal/model"
)

// listKey identifies what an entry covers, so 10.0.0.0/24 and 10.0.0.0-10.0.0.255
// (or Example.com and example.com.) count as the same entry.
func listKey(list, address string) (string, bool) {
	k, err := model.ListEntryKey(address)
	if err != nil {
		return "", false
	}
	return list + "|" + k, true
}

// parseAddresses reads a pasted list: one entry per line or separated by
// spaces or commas, with # or ; starting a comment.
func parseAddresses(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		out = append(out, strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' })...)
	}
	return out
}

// listBulk adds many addresses to one list at once, for blocklists too long to
// enter by hand. With replace the list's entries are swapped for the new ones.
// It is all or nothing: one invalid address and nothing changes.
func (s *Server) listBulk(w http.ResponseWriter, r *http.Request) {
	var in struct {
		List      string `json:"list"`
		Addresses any    `json:"addresses"` // text, or an array of strings
		Comment   string `json:"comment"`
		Replace   bool   `json:"replace"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := model.ValidListName(in.List); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	var addrs []string
	switch v := in.Addresses.(type) {
	case string:
		addrs = parseAddresses(v)
	case []any:
		for _, a := range v {
			str, ok := a.(string)
			if !ok {
				httpErr(w, http.StatusBadRequest, errors.New("addresses must be text or an array of strings"))
				return
			}
			addrs = append(addrs, parseAddresses(str)...)
		}
	default:
		httpErr(w, http.StatusBadRequest, errors.New("addresses must be text or an array of strings"))
		return
	}
	if len(addrs) == 0 {
		httpErr(w, http.StatusBadRequest, errors.New("no addresses given"))
		return
	}
	var bad []string
	for _, a := range addrs {
		if _, ok := listKey(in.List, a); !ok {
			if len(bad) < 5 {
				bad = append(bad, a)
			}
		}
	}
	if len(bad) > 0 {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("nothing was added; these are not valid addresses, networks, ranges or domain names: %s", strings.Join(bad, ", ")))
		return
	}
	var added, skipped int
	s.mutateWith(w, nil, func(c *model.Config) error {
		added, skipped = 0, 0
		if in.Replace {
			kept := c.AddressLists[:0]
			for _, e := range c.AddressLists {
				if e.List != in.List {
					kept = append(kept, e)
				}
			}
			c.AddressLists = kept
		}
		have := map[string]bool{}
		for _, e := range c.AddressLists {
			if k, ok := listKey(e.List, e.Address); ok && !e.Disabled {
				have[k] = true
			}
		}
		for _, a := range addrs {
			k, _ := listKey(in.List, a)
			if have[k] {
				skipped++
				continue
			}
			have[k] = true
			c.AddressLists = append(c.AddressLists, model.AddressEntry{ID: engine.NewID(), List: in.List, Address: a, Comment: in.Comment})
			added++
		}
		return nil
	}, func(out map[string]any) { out["added"], out["skipped"] = added, skipped })
}

func (s *Server) dynamicList(w http.ResponseWriter, r *http.Request) {
	d, err := s.eng.Kernel().ListDynamic()
	labels := s.eng.DomainLabels()
	for i := range d {
		d[i].Domain = labels[d[i].List+"|"+d[i].Address]
	}
	respond(w, orEmpty(d), err)
}

// domainList reports the domain names in address lists: what each resolved to
// and when it is looked up next, or why it couldn't be.
func (s *Server) domainList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.eng.Domains())
}

// dynamicDelete removes one address (list and address given), empties a list
// (list only) or empties them all (neither).
func (s *Server) dynamicDelete(w http.ResponseWriter, r *http.Request) {
	list, address := r.URL.Query().Get("list"), r.URL.Query().Get("address")
	var err error
	switch {
	case address != "" && list == "":
		httpErr(w, http.StatusBadRequest, errors.New("name the list as well as the address"))
		return
	case address != "":
		err = s.eng.Kernel().DelDynamic(list, address)
	default:
		err = s.eng.Kernel().FlushDynamic(list)
	}
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
