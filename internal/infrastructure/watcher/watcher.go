package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Event represents a file system change event.
type Event struct {
	Path      string
	Operation string
	Timestamp time.Time
}

// Handler is called when file changes are detected.
type Handler func(events []Event)

// Config configures the watcher.
type Config struct {
	// Root is the directory to watch.
	Root string

	// Extensions is the list of file extensions to watch (e.g., ".go").
	Extensions []string

	// Exclude is a list of patterns to exclude (e.g., "vendor/", "_test.go").
	Exclude []string

	// Debounce is the duration to wait after the last change before triggering.
	Debounce time.Duration

	// OnChange is called when changes are detected.
	OnChange Handler
}

// DefaultConfig returns a default configuration for watching Go files.
func DefaultConfig(root string, onChange Handler) Config {
	return Config{
		Root:       root,
		Extensions: []string{".go", ".mod", ".sum"},
		Exclude:    []string{"vendor/", "testdata/", ".git/"},
		Debounce:   500 * time.Millisecond,
		OnChange:   onChange,
	}
}

// Watcher watches for file changes and triggers callbacks.
type Watcher struct {
	config    Config
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	events    chan Event
	debouncer *debouncer
}

// New creates a new file watcher.
func New(config Config) *Watcher {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		config: config,
		ctx:    ctx,
		cancel: cancel,
		events: make(chan Event, 100),
	}
	w.debouncer = newDebouncer(config.Debounce, config.OnChange)
	return w
}

// Start begins watching for file changes.
func (w *Watcher) Start() error {
	// Collect initial file state
	files, err := w.collectFiles()
	if err != nil {
		return err
	}

	// Start debouncer
	w.debouncer.start(w.ctx)

	// Start polling
	w.wg.Add(1)
	go w.poll(files)

	return nil
}

// Stop stops the watcher.
func (w *Watcher) Stop() {
	w.cancel()
	w.wg.Wait()
}

// poll checks for file changes periodically.
func (w *Watcher) poll(initial map[string]time.Time) {
	defer w.wg.Done()

	current := initial
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			// Collect current file state
			newFiles, err := w.collectFiles()
			if err != nil {
				continue
			}

			// Compare and detect changes
			w.detectChanges(current, newFiles)
			current = newFiles
		}
	}
}

// collectFiles collects all watched files and their modification times.
func (w *Watcher) collectFiles() (map[string]time.Time, error) {
	files := make(map[string]time.Time)

	err := filepath.Walk(w.config.Root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		// Skip directories
		if info.IsDir() {
			// Check if directory should be excluded
			for _, pattern := range w.config.Exclude {
				if strings.HasSuffix(pattern, "/") {
					dirName := filepath.Base(path)
					if strings.TrimSuffix(pattern, "/") == dirName {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}

		// Check if file should be watched
		if !w.shouldWatch(path) {
			return nil
		}

		files[path] = info.ModTime()
		return nil
	})

	return files, err
}

// shouldWatch returns true if the file should be watched.
func (w *Watcher) shouldWatch(path string) bool {
	// Check extension
	ext := filepath.Ext(path)
	hasValidExt := false
	for _, e := range w.config.Extensions {
		if ext == e {
			hasValidExt = true
			break
		}
	}
	if !hasValidExt {
		return false
	}

	// Check exclusions
	relPath, err := filepath.Rel(w.config.Root, path)
	if err != nil {
		relPath = path
	}

	for _, pattern := range w.config.Exclude {
		if strings.HasPrefix(relPath, pattern) {
			return false
		}
		if strings.Contains(relPath, pattern) {
			return false
		}
	}

	return true
}

// detectChanges compares old and new file states and emits events.
func (w *Watcher) detectChanges(old, new map[string]time.Time) {
	// Check for modified or new files
	for path, newTime := range new {
		if oldTime, exists := old[path]; !exists {
			w.debouncer.add(Event{
				Path:      path,
				Operation: "create",
				Timestamp: time.Now(),
			})
		} else if !newTime.Equal(oldTime) {
			w.debouncer.add(Event{
				Path:      path,
				Operation: "modify",
				Timestamp: time.Now(),
			})
		}
	}

	// Check for deleted files
	for path := range old {
		if _, exists := new[path]; !exists {
			w.debouncer.add(Event{
				Path:      path,
				Operation: "delete",
				Timestamp: time.Now(),
			})
		}
	}
}

// debouncer collects events and triggers the handler after a delay.
type debouncer struct {
	delay   time.Duration
	handler Handler
	mu      sync.Mutex
	events  []Event
	timer   *time.Timer
}

// newDebouncer creates a new debouncer.
func newDebouncer(delay time.Duration, handler Handler) *debouncer {
	return &debouncer{
		delay:   delay,
		handler: handler,
	}
}

// start begins the debouncer.
func (d *debouncer) start(ctx context.Context) {
	go func() {
		<-ctx.Done()
		d.mu.Lock()
		if d.timer != nil {
			d.timer.Stop()
		}
		d.mu.Unlock()
	}()
}

// add adds an event to the debouncer.
func (d *debouncer) add(event Event) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.events = append(d.events, event)

	// Reset or create timer
	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.delay, d.flush)
}

// flush triggers the handler with collected events.
func (d *debouncer) flush() {
	d.mu.Lock()
	events := d.events
	d.events = nil
	d.mu.Unlock()

	if len(events) > 0 && d.handler != nil {
		d.handler(events)
	}
}
