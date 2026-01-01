package watcher

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	handler := func(events []Event) {}
	config := DefaultConfig("/test", handler)

	assert.Equal(t, "/test", config.Root)
	assert.Contains(t, config.Extensions, ".go")
	assert.Contains(t, config.Extensions, ".mod")
	assert.Contains(t, config.Exclude, "vendor/")
	assert.Equal(t, 500*time.Millisecond, config.Debounce)
	assert.NotNil(t, config.OnChange)
}

func TestNew(t *testing.T) {
	config := DefaultConfig("/test", nil)
	w := New(config)

	assert.NotNil(t, w)
	assert.NotNil(t, w.ctx)
	assert.NotNil(t, w.cancel)
	assert.NotNil(t, w.events)
	assert.NotNil(t, w.debouncer)
}

func TestWatcher_ShouldWatch(t *testing.T) {
	config := Config{
		Root:       "/test",
		Extensions: []string{".go", ".mod"},
		Exclude:    []string{"vendor/", "_test.go"},
	}
	w := New(config)

	tests := []struct {
		path     string
		expected bool
	}{
		{"/test/main.go", true},
		{"/test/pkg/handler.go", true},
		{"/test/go.mod", true},
		{"/test/README.md", false},
		{"/test/main.c", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := w.shouldWatch(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWatcher_StartStop(t *testing.T) {
	tmpDir := t.TempDir()

	var mu sync.Mutex
	var receivedEvents []Event

	config := Config{
		Root:       tmpDir,
		Extensions: []string{".go"},
		Exclude:    []string{},
		Debounce:   50 * time.Millisecond,
		OnChange: func(events []Event) {
			mu.Lock()
			receivedEvents = append(receivedEvents, events...)
			mu.Unlock()
		},
	}

	w := New(config)
	err := w.Start()
	require.NoError(t, err)

	// Create a file
	testFile := filepath.Join(tmpDir, "test.go")
	err = os.WriteFile(testFile, []byte("package main"), 0644)
	require.NoError(t, err)

	// Wait for debounce
	time.Sleep(500 * time.Millisecond)

	w.Stop()

	mu.Lock()
	defer mu.Unlock()

	// Should have received create event
	assert.GreaterOrEqual(t, len(receivedEvents), 1)
	if len(receivedEvents) > 0 {
		assert.Equal(t, "create", receivedEvents[0].Operation)
		assert.Contains(t, receivedEvents[0].Path, "test.go")
	}
}

func TestWatcher_DetectModify(t *testing.T) {
	tmpDir := t.TempDir()

	// Create initial file
	testFile := filepath.Join(tmpDir, "test.go")
	err := os.WriteFile(testFile, []byte("package main"), 0644)
	require.NoError(t, err)

	var mu sync.Mutex
	var receivedEvents []Event

	config := Config{
		Root:       tmpDir,
		Extensions: []string{".go"},
		Exclude:    []string{},
		Debounce:   50 * time.Millisecond,
		OnChange: func(events []Event) {
			mu.Lock()
			receivedEvents = append(receivedEvents, events...)
			mu.Unlock()
		},
	}

	w := New(config)
	err = w.Start()
	require.NoError(t, err)

	// Wait for initial state to be collected
	time.Sleep(100 * time.Millisecond)

	// Modify the file
	err = os.WriteFile(testFile, []byte("package main\n// modified"), 0644)
	require.NoError(t, err)

	// Wait for debounce
	time.Sleep(500 * time.Millisecond)

	w.Stop()

	mu.Lock()
	defer mu.Unlock()

	// Should have received modify event
	hasModify := false
	for _, e := range receivedEvents {
		if e.Operation == "modify" {
			hasModify = true
			break
		}
	}
	assert.True(t, hasModify, "should have received modify event")
}

func TestWatcher_DetectDelete(t *testing.T) {
	tmpDir := t.TempDir()

	// Create initial file
	testFile := filepath.Join(tmpDir, "test.go")
	err := os.WriteFile(testFile, []byte("package main"), 0644)
	require.NoError(t, err)

	var mu sync.Mutex
	var receivedEvents []Event

	config := Config{
		Root:       tmpDir,
		Extensions: []string{".go"},
		Exclude:    []string{},
		Debounce:   50 * time.Millisecond,
		OnChange: func(events []Event) {
			mu.Lock()
			receivedEvents = append(receivedEvents, events...)
			mu.Unlock()
		},
	}

	w := New(config)
	err = w.Start()
	require.NoError(t, err)

	// Wait for initial state to be collected
	time.Sleep(100 * time.Millisecond)

	// Delete the file
	err = os.Remove(testFile)
	require.NoError(t, err)

	// Wait for debounce
	time.Sleep(500 * time.Millisecond)

	w.Stop()

	mu.Lock()
	defer mu.Unlock()

	// Should have received delete event
	hasDelete := false
	for _, e := range receivedEvents {
		if e.Operation == "delete" {
			hasDelete = true
			break
		}
	}
	assert.True(t, hasDelete, "should have received delete event")
}

func TestDebouncer(t *testing.T) {
	var mu sync.Mutex
	var receivedEvents []Event

	d := newDebouncer(100*time.Millisecond, func(events []Event) {
		mu.Lock()
		receivedEvents = append(receivedEvents, events...)
		mu.Unlock()
	})

	// Add events rapidly
	d.add(Event{Path: "a.go", Operation: "modify"})
	d.add(Event{Path: "b.go", Operation: "modify"})
	d.add(Event{Path: "c.go", Operation: "modify"})

	// Should not have fired yet
	mu.Lock()
	assert.Empty(t, receivedEvents)
	mu.Unlock()

	// Wait for debounce
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Should have received all events in one batch
	assert.Len(t, receivedEvents, 3)
}

func TestEvent(t *testing.T) {
	e := Event{
		Path:      "/test/main.go",
		Operation: "modify",
		Timestamp: time.Now(),
	}

	assert.Equal(t, "/test/main.go", e.Path)
	assert.Equal(t, "modify", e.Operation)
	assert.False(t, e.Timestamp.IsZero())
}

func TestCollectFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	goFile := filepath.Join(tmpDir, "main.go")
	mdFile := filepath.Join(tmpDir, "README.md")
	err := os.WriteFile(goFile, []byte("package main"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(mdFile, []byte("# README"), 0644)
	require.NoError(t, err)

	config := Config{
		Root:       tmpDir,
		Extensions: []string{".go"},
		Exclude:    []string{},
	}
	w := New(config)

	files, err := w.collectFiles()
	require.NoError(t, err)

	// Should only include .go file
	assert.Len(t, files, 1)
	assert.Contains(t, files, goFile)
	assert.NotContains(t, files, mdFile)
}

func TestCollectFiles_Subdirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory with files
	subDir := filepath.Join(tmpDir, "pkg")
	err := os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	goFile1 := filepath.Join(tmpDir, "main.go")
	goFile2 := filepath.Join(subDir, "handler.go")
	err = os.WriteFile(goFile1, []byte("package main"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(goFile2, []byte("package pkg"), 0644)
	require.NoError(t, err)

	config := Config{
		Root:       tmpDir,
		Extensions: []string{".go"},
		Exclude:    []string{},
	}
	w := New(config)

	files, err := w.collectFiles()
	require.NoError(t, err)

	// Should include both files
	assert.Len(t, files, 2)
	assert.Contains(t, files, goFile1)
	assert.Contains(t, files, goFile2)
}

func TestCollectFiles_ExcludeVendor(t *testing.T) {
	tmpDir := t.TempDir()

	// Create vendor directory
	vendorDir := filepath.Join(tmpDir, "vendor")
	err := os.MkdirAll(vendorDir, 0755)
	require.NoError(t, err)

	mainFile := filepath.Join(tmpDir, "main.go")
	vendorFile := filepath.Join(vendorDir, "dep.go")
	err = os.WriteFile(mainFile, []byte("package main"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(vendorFile, []byte("package dep"), 0644)
	require.NoError(t, err)

	config := DefaultConfig(tmpDir, nil)
	w := New(config)

	files, err := w.collectFiles()
	require.NoError(t, err)

	// Should only include main.go, not vendor files
	assert.Len(t, files, 1)
	assert.Contains(t, files, mainFile)
}
