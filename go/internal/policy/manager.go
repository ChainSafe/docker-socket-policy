package policy

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Manager struct {
	policiesByName  map[string]*Policy
	policiesByImage map[string]*Policy
}

func NewManager(configDir string) (*Manager, error) {
	m := &Manager{
		policiesByName:  make(map[string]*Policy),
		policiesByImage: make(map[string]*Policy),
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("config dir not found, starting with empty policy set", "dir", configDir)
			return m, nil
		}
		return nil, fmt.Errorf("failed to read config directory %s: %w", configDir, err)
	}

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

		m.policiesByName[p.ServiceName] = p
		for _, prefix := range p.AllowedImagePrefixes {
			m.policiesByImage[prefix] = p
		}
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

func (m *Manager) Get(serviceName string) (*Policy, error) {
	p, ok := m.policiesByName[serviceName]
	if !ok {
		return nil, fmt.Errorf("no policy found for service: %s", serviceName)
	}
	return p, nil
}

// GetByImage returns the policy whose prefixes match the reference's
// normalised repository (#84). An invalid reference matches nothing.
func (m *Manager) GetByImage(imageRef string) (*Policy, error) {
	ref, err := ParseImageRef(imageRef)
	if err != nil {
		return nil, err
	}

	for _, p := range m.policiesByName {
		if MatchesImagePrefix(ref.Name, p.AllowedImagePrefixes) {
			return p, nil
		}
	}

	return nil, fmt.Errorf("no policy found for image: %s", imageRef)
}

func (m *Manager) List() []string {
	var names []string
	for name := range m.policiesByName {
		names = append(names, name)
	}
	return names
}
