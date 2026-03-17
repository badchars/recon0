package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractOrigin(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://helpers.bullsheet.me/_next/static/chunks/app/pmm/page.js", "https://helpers.bullsheet.me"},
		{"https://chat.bullsheet.me:443/_next/static/chunks/main.js", "https://chat.bullsheet.me:443"},
		{"http://localhost:3000/bundle.js", "http://localhost:3000"},
		{"not-a-url", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractOrigin(tt.input)
		if got != tt.want {
			t.Errorf("extractOrigin(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseNextJSBuildManifest(t *testing.T) {
	// Realistic _buildManifest.js content (Pages Router style)
	content := `self.__BUILD_MANIFEST = {
		"/__PAGE__": ["static/chunks/pages/__PAGE__-abc123.js"],
		"/": ["static/chunks/pages/index-def456.js"],
		"/pmm": ["static/chunks/pages/pmm-ghi789.js", "static/chunks/shared-jkl012.js"],
		"/api/cid": ["static/chunks/pages/api/cid-mno345.js"],
		"/_app": ["static/chunks/pages/_app-pqr678.js"],
		sortedPages: ["/", "/_app", "/api/cid", "/pmm"]
	};
	self.__BUILD_MANIFEST_CB && self.__BUILD_MANIFEST_CB();`

	chunks := parseNextJSBuildManifest(content, "https://helpers.bullsheet.me")

	if len(chunks) == 0 {
		t.Fatal("expected chunks, got 0")
	}

	// Check that /pmm chunks are discovered
	found := map[string]bool{}
	for _, u := range chunks {
		found[u] = true
	}

	wantChunks := []string{
		"https://helpers.bullsheet.me/_next/static/chunks/pages/pmm-ghi789.js",
		"https://helpers.bullsheet.me/_next/static/chunks/shared-jkl012.js",
		"https://helpers.bullsheet.me/_next/static/chunks/pages/index-def456.js",
	}
	for _, want := range wantChunks {
		if !found[want] {
			t.Errorf("missing chunk URL: %s", want)
		}
	}
}

func TestParseNextJSBuildManifestAppRouter(t *testing.T) {
	// App Router style (newer Next.js)
	content := `self.__BUILD_MANIFEST={
		"__rewrites":{"afterFiles":[],"beforeFiles":[],"fallback":[]},
		"/":["static/chunks/app/page-abc123.js"],
		"/pmm":["static/chunks/app/pmm/page-f16e1cee43be3454.js","static/chunks/699-xyz.js"],
		"/docs":["static/chunks/app/docs/page-111.js"],
		"sortedPages":["/","/_app","/_error","/docs","/pmm"]
	}`

	chunks := parseNextJSBuildManifest(content, "https://helpers.bullsheet.me")

	found := map[string]bool{}
	for _, u := range chunks {
		found[u] = true
	}

	want := "https://helpers.bullsheet.me/_next/static/chunks/app/pmm/page-f16e1cee43be3454.js"
	if !found[want] {
		t.Errorf("missing PMM page chunk: %s\ngot: %v", want, chunks)
	}
}

func TestParseChunkHashPairs(t *testing.T) {
	raw := `272:"b6e4d48929ad5dea",85:"ff97c5f3444512cc",501:"5e27d4df360eaf10"`
	pairs := parseChunkHashPairs(raw)

	if len(pairs) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(pairs))
	}
	if pairs["272"] != "b6e4d48929ad5dea" {
		t.Errorf("pairs[272] = %q, want b6e4d48929ad5dea", pairs["272"])
	}
	if pairs["85"] != "ff97c5f3444512cc" {
		t.Errorf("pairs[85] = %q, want ff97c5f3444512cc", pairs["85"])
	}
}

func TestDetectSPAFrameworksFromURLs(t *testing.T) {
	tmpDir := t.TempDir()

	jc := &jsChainFollower{
		ctx:         context.Background(),
		jsDir:       tmpDir,
		manifest: map[string]string{
			"abc_webpack.js": "https://chat.bullsheet.me/_next/static/chunks/webpack-35ce98ffddede368.js",
			"def_main.js":    "https://chat.bullsheet.me/_next/static/29aT_6Nq1gGvlXbcDgi0P/_buildManifest.js",
		},
		seenHash:     make(map[string]bool),
		scannedFiles: make(map[string]bool),
		detectedSPA:  make(map[string]*spaFrameworkInfo),
	}

	// Create dummy files so readFile doesn't fail
	os.WriteFile(filepath.Join(tmpDir, "abc_webpack.js"), []byte("// webpack"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "def_main.js"), []byte("// build"), 0644)

	jc.detectSPAFrameworks()

	info, ok := jc.detectedSPA["https://chat.bullsheet.me"]
	if !ok {
		t.Fatal("expected Next.js detection for chat.bullsheet.me")
	}
	if info.Framework != "nextjs" {
		t.Errorf("framework = %q, want nextjs", info.Framework)
	}
	if info.BuildID != "29aT_6Nq1gGvlXbcDgi0P" {
		t.Errorf("buildID = %q, want 29aT_6Nq1gGvlXbcDgi0P", info.BuildID)
	}
}

func TestDetectSPAFrameworksFromContent(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a JS file with Next.js marker
	jsContent := `(self.webpackChunk=self.webpackChunk||[]).push([[337],{}]);_N_E=e.O()`
	os.WriteFile(filepath.Join(tmpDir, "abc_main.js"), []byte(jsContent), 0644)

	jc := &jsChainFollower{
		ctx:   context.Background(),
		jsDir: tmpDir,
		manifest: map[string]string{
			"abc_main.js": "https://example.com/assets/main.js",
		},
		seenHash:     make(map[string]bool),
		scannedFiles: make(map[string]bool),
		detectedSPA:  make(map[string]*spaFrameworkInfo),
	}

	jc.detectSPAFrameworks()

	info, ok := jc.detectedSPA["https://example.com"]
	if !ok {
		t.Fatal("expected Next.js detection from content")
	}
	if info.Framework != "nextjs" {
		t.Errorf("framework = %q, want nextjs", info.Framework)
	}
}

func TestDetectAngularFromContent(t *testing.T) {
	tmpDir := t.TempDir()

	jsContent := `platformBrowserDynamic().bootstrapModule(AppModule); // @angular/core`
	os.WriteFile(filepath.Join(tmpDir, "main.js"), []byte(jsContent), 0644)

	jc := &jsChainFollower{
		ctx:   context.Background(),
		jsDir: tmpDir,
		manifest: map[string]string{
			"main.js": "https://por.etoro.com/main-KQPXVTEK.js",
		},
		seenHash:     make(map[string]bool),
		scannedFiles: make(map[string]bool),
		detectedSPA:  make(map[string]*spaFrameworkInfo),
	}

	jc.detectSPAFrameworks()

	info, ok := jc.detectedSPA["https://por.etoro.com"]
	if !ok {
		t.Fatal("expected Angular detection from content")
	}
	if info.Framework != "angular" {
		t.Errorf("framework = %q, want angular", info.Framework)
	}
}

func TestNextJSBuildManifestURLs(t *testing.T) {
	tmpDir := t.TempDir()

	jc := &jsChainFollower{
		ctx:   context.Background(),
		jsDir: tmpDir,
		manifest: map[string]string{
			"abc.js": "https://helpers.bullsheet.me/_next/static/ABC123XY/_buildManifest.js",
		},
		seenHash:     make(map[string]bool),
		scannedFiles: make(map[string]bool),
		detectedSPA:  make(map[string]*spaFrameworkInfo),
	}

	info := &spaFrameworkInfo{
		Framework:  "nextjs",
		Origin:     "https://helpers.bullsheet.me",
		BuildID:    "ABC123XY",
		PublicPath: "/_next/",
	}

	urls := jc.nextjsBuildManifestURLs(info)

	if len(urls) == 0 {
		t.Fatal("expected at least one manifest URL")
	}

	want := "https://helpers.bullsheet.me/_next/static/ABC123XY/_buildManifest.js"
	found := false
	for _, u := range urls {
		if u == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("missing expected URL %s\ngot: %v", want, urls)
	}
}

func TestConstructWebpackChunkURLs(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file with webpack chunk hash map
	jsContent := `var a={272:"b6e4d48929ad5dea",85:"ff97c5f3444512cc"};`
	os.WriteFile(filepath.Join(tmpDir, "runtime.js"), []byte(jsContent), 0644)

	jc := &jsChainFollower{
		ctx:   context.Background(),
		jsDir: tmpDir,
		manifest: map[string]string{
			"runtime.js": "https://example.com/_next/static/chunks/webpack-abc.js",
		},
		seenHash:     make(map[string]bool),
		scannedFiles: make(map[string]bool),
		detectedSPA:  make(map[string]*spaFrameworkInfo),
	}

	info := &spaFrameworkInfo{
		Framework:     "nextjs",
		Origin:        "https://example.com",
		PublicPath:    "/_next/",
		ChunkTemplate: "static/chunks/{ID}.js",
	}

	urls := jc.constructWebpackChunkURLs(info)

	if len(urls) != 2 {
		t.Fatalf("expected 2 chunk URLs, got %d: %v", len(urls), urls)
	}
}
