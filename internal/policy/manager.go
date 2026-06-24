package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manager loads and manages service policies.
type Manager struct {
	policiesByName  map[string]*Policy
	policiesByImage map[string]*Policy
}

// NewManager creates a policy manager and loads all policies from configDir.
func NewManager(configDir string) (*Manager, error) {
	m := &Manager{
		policiesByName:  make(map[string]*Policy),
		policiesByImage: make(map[string]*Policy),
	}

	entries, err := os.ReadDir(configDir)
	if err != nil {
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

	return &p, nil
}

// Get returns a policy by service name.
func (m *Manager) Get(serviceName string) (*Policy, error) {
	p, ok := m.policiesByName[serviceName]
	if !ok {
		return nil, fmt.Errorf("no policy found for service: %s", serviceName)
	}
	return p, nil
}

// GetByImage returns the policy matching an image reference.
// It checks each allowed prefix against the image name.
func (m *Manager) GetByImage(imageRef string) (*Policy, error) {
	imageName := extractImageName(imageRef)

	for _, p := range m.policiesByName {
		for _, prefix := range p.AllowedImagePrefixes {
			if strings.HasPrefix(imageName, prefix) {
				return p, nil
			}
		}
	}

	return nil, fmt.Errorf("no policy found for image: %s", imageRef)
}

// List returns all loaded service names.
func (m *Manager) List() []string {
	var names []string
	for name := range m.policiesByName {
		names = append(names, name)
	}
	return names
}

func extractImageName(imageRef string) string {
	idx := strings.IndexAny(imageRef, ":@")
	if idx == -1 {
		return imageRef
	}
	return imageRef[:idx]
}
