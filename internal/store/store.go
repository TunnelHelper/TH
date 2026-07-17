package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/TunnelHelper/TH/internal/model"
)

var (
	ErrNotFound = errors.New("tunnel not found")
	ErrConflict = errors.New("tunnel generation conflict")
)

type FileStore struct {
	mu       sync.RWMutex
	stateDir string
	dir      string
}

func Open(stateDir string) (*FileStore, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("state directory must be absolute")
	}
	if filepath.Clean(stateDir) == string(filepath.Separator) {
		return nil, errors.New("state directory must not be the filesystem root")
	}
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return nil, fmt.Errorf("prepare state directory: %w", err)
	}
	dir := filepath.Join(stateDir, "tunnels")
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, fmt.Errorf("prepare tunnel store: %w", err)
	}
	store := &FileStore{stateDir: stateDir, dir: dir}
	if _, err := store.List(); err != nil {
		return nil, err
	}
	return store, nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a real directory")
	}
	if err := requireProcessOwnership(info); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func (s *FileStore) List() ([]model.Tunnel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listLocked()
}

func (s *FileStore) listLocked() ([]model.Tunnel, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read tunnel store: %w", err)
	}
	records := make([]model.Tunnel, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !model.ValidID(id) {
			return nil, fmt.Errorf("invalid record filename %q", entry.Name())
		}
		record, err := s.readLocked(id)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name == records[j].Name {
			return records[i].ID < records[j].ID
		}
		return records[i].Name < records[j].Name
	})
	return records, nil
}

func (s *FileStore) Get(id string) (model.Tunnel, error) {
	if !model.ValidID(id) {
		return model.Tunnel{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readLocked(id)
}

func (s *FileStore) Create(record model.Tunnel) error {
	if err := model.Validate(&record); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Lstat(s.path(record.ID)); err == nil {
		return fmt.Errorf("record %s already exists: %w", record.ID, ErrConflict)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.checkNamesLocked(record, ""); err != nil {
		return err
	}
	return s.writeLocked(record)
}

func (s *FileStore) Update(record model.Tunnel, expectedGeneration uint64) error {
	if err := model.Validate(&record); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.readLocked(record.ID)
	if err != nil {
		return err
	}
	if current.Generation != expectedGeneration || record.Generation != expectedGeneration+1 {
		return ErrConflict
	}
	if err := s.checkNamesLocked(record, record.ID); err != nil {
		return err
	}
	return s.writeLocked(record)
}

func (s *FileStore) Delete(id string, expectedGeneration uint64) error {
	if !model.ValidID(id) {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.readLocked(id)
	if err != nil {
		return err
	}
	if record.Generation != expectedGeneration {
		return ErrConflict
	}
	if err := os.RemoveAll(filepath.Join(s.stateDir, "cache", "srv6", id)); err != nil {
		return fmt.Errorf("remove tunnel cache: %w", err)
	}
	if err := os.Remove(s.path(id)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotFound
		}
		return fmt.Errorf("delete tunnel record: %w", err)
	}
	return syncDir(s.dir)
}

func (s *FileStore) checkNamesLocked(candidate model.Tunnel, exceptID string) error {
	records, err := s.listLocked()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.ID == exceptID {
			continue
		}
		if record.Name == candidate.Name {
			return fmt.Errorf("tunnel name %q already exists: %w", candidate.Name, ErrConflict)
		}
		if candidate.Interface != "" && record.Interface == candidate.Interface {
			return fmt.Errorf("interface %q is already managed: %w", candidate.Interface, ErrConflict)
		}
		if candidate.Spec.XFRMStatic != nil {
			if collidesStatic(candidate.Spec.XFRMStatic, record) {
				return fmt.Errorf("XFRM if_id or req_id collides with %q: %w", record.Name, ErrConflict)
			}
		}
		if candidate.Spec.XFRMIKEv2 != nil {
			if collidesIKE(candidate.Spec.XFRMIKEv2, record) {
				return fmt.Errorf("XFRM if_id or req_id collides with %q: %w", record.Name, ErrConflict)
			}
		}
		if candidate.Spec.SRv6 != nil && record.Spec.SRv6 != nil && candidate.Spec.SRv6.Table == record.Spec.SRv6.Table {
			return fmt.Errorf("SRv6 table %d is already managed by %q: %w", candidate.Spec.SRv6.Table, record.Name, ErrConflict)
		}
		if collidesRulePriority(candidate, record) {
			return fmt.Errorf("policy-rule priority collides with %q: %w", record.Name, ErrConflict)
		}
		if collidesManagedRoute(candidate, record) {
			return fmt.Errorf("managed route collides with %q: %w", record.Name, ErrConflict)
		}
	}
	return nil
}

func collidesManagedRoute(a, b model.Tunnel) bool {
	left := model.ManagedRouteClaims(a)
	right := model.ManagedRouteClaims(b)
	for _, table := range model.ExclusiveRouteTables(a) {
		if routeTableIsUsed(table, right, model.ExclusiveRouteTables(b)) {
			return true
		}
	}
	for _, table := range model.ExclusiveRouteTables(b) {
		if routeTableIsUsed(table, left, model.ExclusiveRouteTables(a)) {
			return true
		}
	}
	for _, l := range left {
		for _, r := range right {
			if l.Table == r.Table && l.Prefix == r.Prefix {
				return true
			}
		}
	}
	return false
}

func routeTableIsUsed(table int, claims []model.RouteClaim, exclusive []int) bool {
	for _, other := range exclusive {
		if table == other {
			return true
		}
	}
	for _, claim := range claims {
		if table == claim.Table {
			return true
		}
	}
	return false
}

func collidesRulePriority(a, b model.Tunnel) bool {
	left := model.ManagedRulePriorities(a)
	right := model.ManagedRulePriorities(b)
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}
	return false
}

func collidesStatic(spec *model.XFRMStaticSpec, record model.Tunnel) bool {
	if other := record.Spec.XFRMStatic; other != nil {
		return spec.IfID == other.IfID || spec.ReqID == other.ReqID
	}
	if other := record.Spec.XFRMIKEv2; other != nil {
		return spec.IfID == other.IfID || spec.ReqID == other.ReqID
	}
	return false
}

func collidesIKE(spec *model.XFRMIKEv2Spec, record model.Tunnel) bool {
	if other := record.Spec.XFRMStatic; other != nil {
		return spec.IfID == other.IfID || spec.ReqID == other.ReqID
	}
	if other := record.Spec.XFRMIKEv2; other != nil {
		return spec.IfID == other.IfID || spec.ReqID == other.ReqID
	}
	return false
}

func (s *FileStore) readLocked(id string) (model.Tunnel, error) {
	info, err := os.Lstat(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return model.Tunnel{}, ErrNotFound
	}
	if err != nil {
		return model.Tunnel{}, fmt.Errorf("inspect tunnel record %s: %w", id, err)
	}
	if !info.Mode().IsRegular() {
		return model.Tunnel{}, fmt.Errorf("tunnel record %s is not a regular file", id)
	}
	if err := requireProcessOwnership(info); err != nil {
		return model.Tunnel{}, fmt.Errorf("tunnel record %s: %w", id, err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return model.Tunnel{}, fmt.Errorf("tunnel record %s has unsafe mode %04o", id, info.Mode().Perm())
	}
	if info.Size() > 4<<20 {
		return model.Tunnel{}, fmt.Errorf("tunnel record %s exceeds 4 MiB", id)
	}
	file, err := os.Open(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return model.Tunnel{}, ErrNotFound
	}
	if err != nil {
		return model.Tunnel{}, fmt.Errorf("open tunnel record %s: %w", id, err)
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, 4<<20))
	decoder.DisallowUnknownFields()
	var record model.Tunnel
	if err := decoder.Decode(&record); err != nil {
		return model.Tunnel{}, fmt.Errorf("decode tunnel record %s: %w", id, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return model.Tunnel{}, fmt.Errorf("decode tunnel record %s: expected exactly one JSON value", id)
	}
	if record.ID != id {
		return model.Tunnel{}, fmt.Errorf("record %s contains mismatched id %q", id, record.ID)
	}
	if err := model.Validate(&record); err != nil {
		return model.Tunnel{}, fmt.Errorf("validate tunnel record %s: %w", id, err)
	}
	return record, nil
}

func (s *FileStore) writeLocked(record model.Tunnel) error {
	temporary, err := os.CreateTemp(s.dir, ".record-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary record: %w", err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return fmt.Errorf("protect temporary record: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("encode tunnel record: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync tunnel record: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close tunnel record: %w", err)
	}
	if err := os.Rename(temporaryName, s.path(record.ID)); err != nil {
		return fmt.Errorf("commit tunnel record: %w", err)
	}
	committed = true
	return syncDir(s.dir)
}

func (s *FileStore) path(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory: %w", err)
	}
	return nil
}

func requireProcessOwnership(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine filesystem ownership")
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("path is owned by UID %d, expected UID %d", stat.Uid, os.Geteuid())
	}
	return nil
}
