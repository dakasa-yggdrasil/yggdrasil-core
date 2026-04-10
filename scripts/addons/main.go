package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed templates
var templateFS embed.FS

type addonSpec struct {
	Name         string
	Description  string
	Dependencies []string
}

var addonSpecs = map[string]addonSpec{
	"auth": {
		Name:        "auth",
		Description: "Generate JWT header normalization, authenticated routes, and a token helper script.",
	},
	"postgres": {
		Name:        "postgres",
		Description: "Generate PostgreSQL bootstrap helpers and a Go connectivity script.",
	},
	"goose": {
		Name:         "goose",
		Description:  "Generate Goose migration assets and the Go migration runner.",
		Dependencies: []string{"postgres"},
	},
	"redis": {
		Name:        "redis",
		Description: "Generate Redis bootstrap helpers and a Go connectivity script.",
	},
	"rabbitmq": {
		Name:        "rabbitmq",
		Description: "Generate RabbitMQ bootstrap helpers, message package, and a Go connectivity script.",
	},
	"observability": {
		Name:        "observability",
		Description: "Generate Dakasa observability bootstrap with zap logging and HTTP metrics middleware.",
	},
	"outbox": {
		Name:         "outbox",
		Description:  "Generate Dakasa dual-path outbox helpers, workers, and migration assets.",
		Dependencies: []string{"postgres", "rabbitmq", "redis"},
	},
	"temporal": {
		Name:        "temporal",
		Description: "Generate Temporal worker bootstrap, a sample workflow, and helper scripts.",
	},
	"websocket": {
		Name:        "websocket",
		Description: "Generate a reusable WebSocket hub, HTTP endpoints, and a CLI probe script.",
	},
}

type templateContext struct {
	ModulePath  string
	ServiceName string
	ServiceSlug string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list":
		listAddons()
	case "add":
		if err := addCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "addon error: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("yggdrasil-core addons")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go run ./scripts/addons list")
	fmt.Println("  go run ./scripts/addons add --name postgres")
}

func listAddons() {
	names := make([]string, 0, len(addonSpecs))
	for name := range addonSpecs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		spec := addonSpecs[name]
		if len(spec.Dependencies) == 0 {
			fmt.Printf("- %s: %s\n", spec.Name, spec.Description)
			continue
		}
		fmt.Printf("- %s: %s (depends on: %s)\n", spec.Name, spec.Description, strings.Join(spec.Dependencies, ", "))
	}
}

func addCommand(args []string) error {
	fsFlags := flag.NewFlagSet("add", flag.ContinueOnError)
	name := fsFlags.String("name", "", "Addon name")
	force := fsFlags.Bool("force", false, "Overwrite existing files")
	skipTidy := fsFlags.Bool("skip-tidy", false, "Skip go mod tidy after file generation")
	if err := fsFlags.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*name) == "" {
		return errors.New("addon name is required")
	}

	root, err := findRepoRoot()
	if err != nil {
		return err
	}

	ctx, err := loadTemplateContext(root)
	if err != nil {
		return err
	}

	selection, err := resolveAddons(*name)
	if err != nil {
		return err
	}

	for _, addon := range selection {
		if err := materializeAddon(root, ctx, addon, *force); err != nil {
			return err
		}
	}

	if !*skipTidy {
		if err := runGoModTidy(root); err != nil {
			return err
		}
	}

	return nil
}

func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	cur := cwd
	for {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	return "", errors.New("could not find repository root (go.mod not found)")
}

func loadTemplateContext(root string) (templateContext, error) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return templateContext{}, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		modulePath := strings.TrimSpace(strings.TrimPrefix(line, "module "))
		serviceName := filepath.Base(modulePath)
		return templateContext{
			ModulePath:  modulePath,
			ServiceName: serviceName,
			ServiceSlug: strings.ReplaceAll(serviceName, "-", "_"),
		}, nil
	}

	return templateContext{}, errors.New("module path not found in go.mod")
}

func resolveAddons(name string) ([]string, error) {
	name = strings.TrimSpace(name)
	spec, ok := addonSpecs[name]
	if !ok {
		return nil, fmt.Errorf("unknown addon %q", name)
	}

	var ordered []string
	visited := map[string]bool{}
	var visit func(addonSpec)
	visit = func(current addonSpec) {
		if visited[current.Name] {
			return
		}
		visited[current.Name] = true
		for _, depName := range current.Dependencies {
			dep := addonSpecs[depName]
			visit(dep)
		}
		ordered = append(ordered, current.Name)
	}

	visit(spec)
	return ordered, nil
}

func materializeAddon(root string, ctx templateContext, addon string, force bool) error {
	baseDir := filepath.ToSlash(filepath.Join("templates", addon))

	return fs.WalkDir(templateFS, baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		raw, err := templateFS.ReadFile(path)
		if err != nil {
			return err
		}

		rel := strings.TrimPrefix(path, baseDir+"/")
		targetRel := strings.TrimSuffix(rel, ".tmpl")
		targetPath := filepath.Join(root, filepath.FromSlash(targetRel))

		if _, err := os.Stat(targetPath); err == nil && !force {
			fmt.Printf("skip %s (already exists)\n", targetRel)
			return nil
		}

		rendered := renderTemplate(raw, ctx)
		if strings.HasSuffix(targetPath, ".go") {
			rendered = mustFormatGo(rendered)
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(targetPath, rendered, 0o644); err != nil {
			return err
		}

		fmt.Printf("wrote %s\n", targetRel)
		return nil
	})
}

func renderTemplate(raw []byte, ctx templateContext) []byte {
	replacer := strings.NewReplacer(
		"{{MODULE_PATH}}", ctx.ModulePath,
		"{{SERVICE_NAME}}", ctx.ServiceName,
		"{{SERVICE_SLUG}}", ctx.ServiceSlug,
	)
	return []byte(replacer.Replace(string(raw)))
}

func mustFormatGo(raw []byte) []byte {
	formatted, err := format.Source(raw)
	if err != nil {
		return raw
	}
	return formatted
}

func runGoModTidy(root string) error {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
