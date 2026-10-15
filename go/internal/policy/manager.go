package policy

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// validContainerName is a Docker container name without the optional leading
// slash (#85).
var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

var (
	groupGIDRe  = regexp.MustCompile(`^[0-9]+$`)
	groupNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*\$?$`)
)

// checkGroupAdd validates container_config.group_add (#93): each entry is a
// decimal GID that fits in 32 bits or a group name of at most 32 characters;
// the root group (0 in any decimal form, or root) and duplicates (by GID
// value for numbers) are refused.
func checkGroupAdd(file string, groups []string) error {
	seen := make(map[string]bool)
	for _, g := range groups {
		var key string
		switch {
		case groupGIDRe.MatchString(g):
			gid, err := strconv.ParseUint(g, 10, 32)
			if err != nil {
				return fmt.Errorf("policy file %s: invalid group_add entry %q (want a decimal GID or a group name)", file, g)
			}
			if gid == 0 {
				return fmt.Errorf("policy file %s: group_add entry %q is the root group, which is not allowed", file, g)
			}
			key = "gid:" + strconv.FormatUint(gid, 10)
		case len(g) <= 32 && groupNameRe.MatchString(g):
			if g == "root" {
				return fmt.Errorf("policy file %s: group_add entry %q is the root group, which is not allowed", file, g)
			}
			key = "name:" + g
		default:
			return fmt.Errorf("policy file %s: invalid group_add entry %q (want a decimal GID or a group name)", file, g)
		}
		if seen[key] {
			return fmt.Errorf("policy file %s: duplicate group_add entry %q", file, g)
		}
		seen[key] = true
	}
	return nil
}

// ValidContainerName reports whether name is a valid Docker container name.
func ValidContainerName(name string) bool {
	return validContainerName.MatchString(name)
}

type Manager struct {
	policiesByName map[string]*Policy
	// ordered holds the policies sorted by service_name, so selection never
	// depends on map iteration order (#85).
	ordered []*Policy
}

// NewManagerFromPolicies builds a manager without load-time validation, as
// Rust's Manager::from_map and TypeScript's Manager.fromPolicies do. Tests
// use it to reach states that NewManager refuses, such as ambiguity. The
// prefixes are used as given, so they must already be normalised.
func NewManagerFromPolicies(policies ...*Policy) *Manager {
	m := &Manager{policiesByName: make(map[string]*Policy)}
	for _, p := range policies {
		m.policiesByName[p.ServiceName] = p
	}
	m.sortPolicies()
	return m
}

func (m *Manager) sortPolicies() {
	m.ordered = m.ordered[:0]
	for _, p := range m.policiesByName {
		m.ordered = append(m.ordered, p)
	}
	sort.Slice(m.ordered, func(i, j int) bool { return m.ordered[i].ServiceName < m.ordered[j].ServiceName })
}

func NewManager(configDir string) (*Manager, error) {
	m := &Manager{
		policiesByName: make(map[string]*Policy),
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("config dir not found, starting with empty policy set", "dir", configDir)
			return m, nil
		}
		return nil, fmt.Errorf("failed to read config directory %s: %w", configDir, err)
	}

	fileOf := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		filePath := filepath.Join(configDir, entry.Name())
		p, err := loadPolicy(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load policy %s: %w", entry.Name(), err)
		}

		// A second file with the same service_name used to replace the
		// first silently (#85).
		if prev, ok := fileOf[p.ServiceName]; ok {
			return nil, fmt.Errorf("policies in %s and %s both use service_name %q", prev, entry.Name(), p.ServiceName)
		}
		fileOf[p.ServiceName] = entry.Name()
		m.policiesByName[p.ServiceName] = p
	}

	m.sortPolicies()
	if err := m.checkConflicts(fileOf); err != nil {
		return nil, err
	}
	return m, nil
}

func loadPolicy(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if p.ServiceName == "" {
		return nil, fmt.Errorf("policy file %s missing required field 'service_name'", filePath)
	}
	if len(p.AllowedImagePrefixes) == 0 {
		return nil, fmt.Errorf("policy file %s missing required field 'allowed_image_prefixes'", filePath)
	}
	if p.ContainerNames != nil && len(p.ContainerNames) == 0 {
		return nil, fmt.Errorf("policy file %s: container_names must not be empty", filePath)
	}
	for _, n := range p.ContainerNames {
		if !ValidContainerName(n) {
			return nil, fmt.Errorf("policy file %s: invalid container name %q in container_names", filePath, n)
		}
	}

	if err := checkGroupAdd(filepath.Base(filePath), p.ContainerConfig.GroupAdd); err != nil {
		return nil, err
	}
	// An empty group_add is the same as an unset one.
	if len(p.ContainerConfig.GroupAdd) == 0 {
		p.ContainerConfig.GroupAdd = nil
	}

	// Prefixes are compared in normalised form (#84).
	for i, prefix := range p.AllowedImagePrefixes {
		normalized, err := NormalizeImagePrefix(prefix)
		if err != nil {
			return nil, fmt.Errorf("policy file %s has an invalid allowed_image_prefixes entry %q", filePath, prefix)
		}
		p.AllowedImagePrefixes[i] = normalized
	}

	return &p, nil
}

// checkConflicts fails when two policies could both be selected for one
// create: their normalised image prefixes share a namespace, and one of them
// accepts any name or their container_names intersect (#85).
func (m *Manager) checkConflicts(fileOf map[string]string) error {
	for i, a := range m.ordered {
		for _, b := range m.ordered[i+1:] {
			pa, pb, ok := overlappingPrefixes(a.AllowedImagePrefixes, b.AllowedImagePrefixes)
			if !ok {
				continue
			}
			var reason string
			switch {
			case a.ContainerNames == nil:
				reason = fmt.Sprintf("%q has no container_names", a.ServiceName)
			case b.ContainerNames == nil:
				reason = fmt.Sprintf("%q has no container_names", b.ServiceName)
			default:
				shared := sharedName(a.ContainerNames, b.ContainerNames)
				if shared == "" {
					continue
				}
				reason = fmt.Sprintf("both accept container name %q", shared)
			}
			return fmt.Errorf("conflicting policies %q (%s) and %q (%s): image prefixes %q and %q overlap and %s",
				a.ServiceName, fileOf[a.ServiceName], b.ServiceName, fileOf[b.ServiceName], pa, pb, reason)
		}
	}
	return nil
}

// overlappingPrefixes returns the first pair of prefixes where one equals the
// other or is a namespace (/) prefix of it.
func overlappingPrefixes(as, bs []string) (string, string, bool) {
	for _, a := range as {
		for _, b := range bs {
			if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
				return a, b, true
			}
		}
	}
	return "", "", false
}

// sharedName returns the smallest name in both lists, or "".
func sharedName(as, bs []string) string {
	shared := ""
	for _, a := range as {
		for _, b := range bs {
			if a == b && (shared == "" || a < shared) {
				shared = a
			}
		}
	}
	return shared
}

func (m *Manager) Get(serviceName string) (*Policy, error) {
	p, ok := m.policiesByName[serviceName]
	if !ok {
		return nil, fmt.Errorf("no policy found for service: %s", serviceName)
	}
	return p, nil
}

// GetByImage returns the first policy, sorted by service_name, whose prefixes
// match the reference's normalised repository (#84, #85). An invalid
// reference matches nothing.
func (m *Manager) GetByImage(imageRef string) (*Policy, error) {
	ref, err := ParseImageRef(imageRef)
	if err != nil {
		return nil, err
	}

	if ps := m.MatchingImage(ref.Name); len(ps) > 0 {
		return ps[0], nil
	}

	return nil, fmt.Errorf("no policy found for image: %s", imageRef)
}

// MatchingImage returns the policies, sorted by service_name, whose prefixes
// match a normalised repository name (#85).
func (m *Manager) MatchingImage(name string) []*Policy {
	var out []*Policy
	for _, p := range m.ordered {
		if MatchesImagePrefix(name, p.AllowedImagePrefixes) {
			out = append(out, p)
		}
	}
	return out
}

// SelectForCreate returns the one policy whose image prefixes match the
// normalised repository of imageRef and which accepts the container name
// (empty for a create without ?name=). No match, or more than one, is an
// error whose text is the deny message (#85).
func (m *Manager) SelectForCreate(imageRef, name string) (*Policy, error) {
	ref, err := ParseImageRef(imageRef)
	if err != nil {
		return nil, err
	}

	matching := m.MatchingImage(ref.Name)
	var candidates []*Policy
	for _, p := range matching {
		if p.AcceptsName(name) {
			candidates = append(candidates, p)
		}
	}

	switch {
	case len(matching) == 0:
		return nil, fmt.Errorf("image %s not allowed by any policy", imageRef)
	case len(candidates) == 0 && name == "":
		return nil, fmt.Errorf("image %s requires a container name", imageRef)
	case len(candidates) == 0:
		return nil, fmt.Errorf("container name %s not allowed for image %s by any policy", name, imageRef)
	case len(candidates) > 1:
		names := make([]string, len(candidates))
		for i, p := range candidates {
			names[i] = p.ServiceName
		}
		return nil, fmt.Errorf("ambiguous policy for image %s and name %s: %s", imageRef, name, strings.Join(names, ", "))
	}
	return candidates[0], nil
}

// Covering returns the policies, sorted by service_name, whose covered names
// include name (#86).
func (m *Manager) Covering(name string) []*Policy {
	var out []*Policy
	for _, p := range m.ordered {
		for _, n := range p.CoveredNames() {
			if n == name {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func (m *Manager) List() []string {
	var names []string
	for _, p := range m.ordered {
		names = append(names, p.ServiceName)
	}
	return names
}
