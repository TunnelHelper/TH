package guard

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var forbiddenText = []string{
	"/etc/network/interfaces",
	"/etc/netplan",
	"/etc/NetworkManager",
	"/etc/systemd/network",
	"/etc/wireguard",
	"/etc/amnezia",
	"/etc/swanctl",
	"/etc/openvpn",
}

func TestProductionCodeDoesNotExecuteCommands(t *testing.T) {
	root := repositoryRoot(t)
	set := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(set, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			importDeclaration, ok := declaration.(*ast.GenDecl)
			if !ok || importDeclaration.Tok != token.IMPORT {
				continue
			}
			for _, spec := range importDeclaration.Specs {
				importSpec := spec.(*ast.ImportSpec)
				if strings.Trim(importSpec.Path.Value, "\"") == "os/exec" {
					t.Errorf("production code imports os/exec: %s", relative(root, path))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProductionCodeDoesNotReferenceForbiddenConfiguration(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" || entry.Name() == "docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		line := 0
		for scanner.Scan() {
			line++
			text := scanner.Text()
			for _, forbidden := range forbiddenText {
				if strings.Contains(text, forbidden) {
					t.Errorf("forbidden configuration path %q at %s:%d", forbidden, relative(root, path), line)
				}
			}
			if strings.Contains(strings.ToLower(text), "openvpn") {
				t.Errorf("OpenVPN reference remains at %s:%d", relative(root, path), line)
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source file")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locate repository root: %v", err)
	}
	return root
}

func relative(root, path string) string {
	value, err := filepath.Rel(root, path)
	if err != nil {
		return fmt.Sprintf("%s", path)
	}
	return value
}
