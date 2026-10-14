package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// ImageRef is a parsed image reference (#84). Name is the normalised
// repository: the registry host, lower-cased, and the path; Docker Hub's host
// is dropped, and so is library/ before a single-component name, so alpine,
// library/alpine and docker.io/library/alpine are all alpine. Tag and Digest
// are empty when absent.
type ImageRef struct {
	Name   string
	Tag    string
	Digest string
}

var (
	defaultRegistries = map[string]bool{"docker.io": true, "index.docker.io": true, "registry-1.docker.io": true}
	domainRe          = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]+)?$`)
	pathComponentRe   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	tagRe             = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	sha256DigestRe    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// ParseImageRef parses [registry/]repository[:tag][@digest] the way Docker
// does (#84). The digest follows the first @; the tag follows the last : after
// the last /, so a registry port is not a tag. The first path component is a
// registry host when it contains . or : or is localhost. Only the host is
// lower-cased: upper case in the path is invalid. The digest is checked by
// CheckImageTag, not here.
func ParseImageRef(ref string) (ImageRef, error) {
	invalid := fmt.Errorf(`invalid image reference "%s"`, ref)
	rest, digest, hasDigest := strings.Cut(ref, "@")
	if hasDigest && digest == "" {
		return ImageRef{}, invalid
	}
	afterSlash := strings.LastIndexByte(rest, '/') + 1
	name, tag := rest, ""
	if i := strings.LastIndexByte(rest[afterSlash:], ':'); i != -1 {
		name, tag = rest[:afterSlash+i], rest[afterSlash+i+1:]
		if !tagRe.MatchString(tag) {
			return ImageRef{}, invalid
		}
	}
	normalized, ok := normalizeName(name)
	if !ok {
		return ImageRef{}, invalid
	}
	return ImageRef{Name: normalized, Tag: tag, Digest: digest}, nil
}

func normalizeName(name string) (string, bool) {
	domain, path := "", name
	if first, rest, ok := strings.Cut(name, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		domain, path = strings.ToLower(first), rest
		if !domainRe.MatchString(domain) {
			return "", false
		}
	}
	for _, c := range strings.Split(path, "/") {
		if !pathComponentRe.MatchString(c) {
			return "", false
		}
	}
	if defaultRegistries[domain] {
		domain = ""
	}
	full := path
	if domain != "" {
		full = domain + "/" + path
	} else if official, ok := strings.CutPrefix(path, "library/"); ok && !strings.Contains(official, "/") {
		full = official
	}
	if len(full) > 255 {
		return "", false
	}
	return full, true
}

// NormalizeImagePrefix normalises a policy prefix at load time (#84). A
// prefix names a repository or a namespace, so a tag or digest makes it
// invalid.
func NormalizeImagePrefix(prefix string) (string, error) {
	r, err := ParseImageRef(prefix)
	if err != nil {
		return "", err
	}
	if r.Tag != "" || r.Digest != "" {
		return "", fmt.Errorf(`image prefix "%s" has a tag or digest`, prefix)
	}
	return r.Name, nil
}

// MatchesImagePrefix matches a normalised repository against normalised
// prefixes on namespace boundaries ("prefix" or "prefix/..."), never a bare
// substring.
func MatchesImagePrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	return false
}

// CheckImageTag applies a policy's digest and tag rules to a parsed
// reference: the digest must be allowed and well-formed, the tag must match
// image_tag_pattern. Shared by the registry gate (create) and the router
// (pull, #83).
func CheckImageTag(p *Policy, r ImageRef) error {
	if r.Digest != "" {
		if len(r.Digest) > 128 {
			return fmt.Errorf("image tag/digest exceeds 128 characters")
		}
		if !p.ImageDigestAllowed {
			return fmt.Errorf("image digests not allowed for service %s", p.ServiceName)
		}
		if !sha256DigestRe.MatchString(r.Digest) {
			return fmt.Errorf("invalid digest format: %s", r.Digest)
		}
	}
	if r.Tag != "" {
		if len(r.Tag) > 128 {
			return fmt.Errorf("image tag/digest exceeds 128 characters")
		}
		if p.ImageTagPattern != "" {
			matched, err := regexp.MatchString(p.ImageTagPattern, r.Tag)
			if err != nil {
				return fmt.Errorf("invalid tag pattern regex: %w", err)
			}
			if !matched {
				return fmt.Errorf("image tag %q does not match pattern %q", r.Tag, p.ImageTagPattern)
			}
		}
	}
	return nil
}
