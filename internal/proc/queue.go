package proc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/atlet99/ht-notifier/internal/config"
	"github.com/atlet99/ht-notifier/internal/harbor"
	"github.com/atlet99/ht-notifier/internal/notif"
	"github.com/atlet99/ht-notifier/internal/obs"
	"go.uber.org/zap"
)

// Event represents a processing event
type Event struct {
	ID        string
	Type      string
	Data      map[string]interface{}
	CreatedAt time.Time
	Retries   int
}

// Queue represents a processing queue
type Queue struct {
	events    chan *Event
	maxSize   int
	logger    *zap.Logger
	metrics   *obs.Metrics
	mu        sync.RWMutex
	closed    bool
	closeChan chan struct{}
}

// NewQueue creates a new processing queue
func NewQueue(maxSize int, logger *zap.Logger, metrics *obs.Metrics) *Queue {
	return &Queue{
		events:    make(chan *Event, maxSize),
		maxSize:   maxSize,
		logger:    logger,
		metrics:   metrics,
		closeChan: make(chan struct{}),
	}
}

// Push adds an event to the queue
func (q *Queue) Push(event *Event) error {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.closed {
		return ErrQueueClosed
	}

	select {
	case q.events <- event:
		q.metrics.QueueDepthGauge.Set(float64(len(q.events)))
		q.logger.Info("Event queued",
			zap.String("event_id", event.ID),
			zap.String("event_type", event.Type),
			zap.Int("queue_depth", len(q.events)))
		return nil
	default:
		q.metrics.QueueErrorsTotal.WithLabelValues("full").Inc()
		return ErrQueueFull
	}
}

// Pop removes and returns an event from the queue
func (q *Queue) Pop() (*Event, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if q.closed {
		return nil, ErrQueueClosed
	}

	select {
	case event := <-q.events:
		q.metrics.QueueDepthGauge.Set(float64(len(q.events)))
		return event, nil
	case <-q.closeChan:
		return nil, ErrQueueClosed
	}
}

// Size returns the current queue size
func (q *Queue) Size() int {
	return len(q.events)
}

// Close closes the queue
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return nil
	}

	q.closed = true
	close(q.closeChan)
	close(q.events)

	return nil
}

// IsClosed returns true if the queue is closed
func (q *Queue) IsClosed() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.closed
}

// Worker represents a processing worker
type Worker struct {
	id           int
	queue        *Queue
	processor    EventProcessor
	logger       *zap.Logger
	metrics      *obs.Metrics
	retryConfig  config.RetryConfig
	stopChan     chan struct{}
	wg           *sync.WaitGroup
	harborClient *harbor.Client
	notifiers    []notif.Notifier
}

// EventProcessor defines the interface for processing events
type EventProcessor interface {
	Process(ctx context.Context, event *Event) error
}

// NewWorker creates a new worker
func NewWorker(id int, queue *Queue, processor EventProcessor, logger *zap.Logger,
	metrics *obs.Metrics, retryConfig config.RetryConfig, harborClient *harbor.Client,
	notifiers []notif.Notifier) *Worker {
	return &Worker{
		id:           id,
		queue:        queue,
		processor:    processor,
		logger:       logger,
		metrics:      metrics,
		retryConfig:  retryConfig,
		stopChan:     make(chan struct{}),
		harborClient: harborClient,
		notifiers:    notifiers,
	}
}

// Start starts the worker
func (w *Worker) Start(wg *sync.WaitGroup) {
	w.wg = wg
	wg.Add(1)

	go w.run()
}

// Stop stops the worker
func (w *Worker) Stop() {
	close(w.stopChan)
	w.wg.Wait()
}

// run is the main worker loop
func (w *Worker) run() {
	defer w.wg.Done()

	w.logger.Info("Worker started", zap.Int("worker_id", w.id))

	for {
		select {
		case <-w.stopChan:
			w.logger.Info("Worker stopping", zap.Int("worker_id", w.id))
			return
		default:
			event, err := w.queue.Pop()
			if err != nil {
				if err == ErrQueueClosed {
					w.logger.Info("Worker stopping, queue closed", zap.Int("worker_id", w.id))
					return
				}
				w.logger.Error("Failed to pop event from queue", zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			w.processEvent(event)
		}
	}
}

// processEvent processes a single event with retry logic
func (w *Worker) processEvent(event *Event) {
	startTime := time.Now()

	w.logger.Info("Processing event",
		zap.String("event_id", event.ID),
		zap.String("event_type", event.Type),
		zap.Int("retries", event.Retries))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err := w.processor.Process(ctx, event)
	if err != nil {
		w.logger.Error("Event processing failed",
			zap.String("event_id", event.ID),
			zap.Error(err))

		if event.Retries < w.retryConfig.MaxAttempts {
			event.Retries++
			event.CreatedAt = time.Now()

			// Exponential backoff with jitter
			backoff := w.calculateBackoff(event.Retries)
			w.logger.Info("Retrying event",
				zap.String("event_id", event.ID),
				zap.Int("retry_attempt", event.Retries),
				zap.Duration("backoff", backoff))

			time.AfterFunc(backoff, func() {
				if err := w.queue.Push(event); err != nil {
					w.logger.Error("Failed to retry event",
						zap.String("event_id", event.ID),
						zap.Error(err))
				}
			})
		} else {
			w.logger.Error("Event processing failed permanently",
				zap.String("event_id", event.ID),
				zap.Error(err))
			w.metrics.ProcessingErrorsTotal.WithLabelValues("permanent").Inc()
		}
	} else {
		w.logger.Info("Event processed successfully",
			zap.String("event_id", event.ID),
			zap.Duration("duration", time.Since(startTime)))
	}

	w.metrics.ProcessingDurationHistogram.WithLabelValues(event.Type).Observe(time.Since(startTime).Seconds())
	w.metrics.ProcessedEventsTotal.WithLabelValues("success").Inc()
}

// calculateBackoff calculates exponential backoff with jitter
func (w *Worker) calculateBackoff(attempt int) time.Duration {
	backoff := w.retryConfig.InitialBackoff * time.Duration(1<<uint(attempt-1))
	if backoff > w.retryConfig.MaxBackoff {
		backoff = w.retryConfig.MaxBackoff
	}

	// Add jitter (±25%)
	jitter := float64(backoff) * 0.25
	jitterDuration := time.Duration(jitter)

	return backoff + time.Duration(float64(jitterDuration)/2) - time.Duration(float64(jitterDuration)/2)
}

// Pool represents a worker pool
type Pool struct {
	workers []*Worker
	queue   *Queue
	logger  *zap.Logger
	metrics *obs.Metrics
	wg      *sync.WaitGroup
	maxSize int
}

// NewPool creates a new worker pool
func NewPool(size int, queue *Queue, processor EventProcessor, logger *zap.Logger,
	metrics *obs.Metrics, retryConfig config.RetryConfig, harborClient *harbor.Client,
	notifiers []notif.Notifier) *Pool {
	pool := &Pool{
		workers: make([]*Worker, size),
		queue:   queue,
		logger:  logger,
		metrics: metrics,
		wg:      &sync.WaitGroup{},
		maxSize: size,
	}

	for i := 0; i < size; i++ {
		worker := NewWorker(i, queue, processor, logger, metrics, retryConfig, harborClient, notifiers)
		pool.workers[i] = worker
	}

	return pool
}

// Start starts all workers in the pool
func (p *Pool) Start() {
	p.logger.Info("Starting worker pool", zap.Int("size", p.maxSize))

	for _, worker := range p.workers {
		worker.Start(p.wg)
	}
}

// Stop stops all workers in the pool
func (p *Pool) Stop() {
	p.logger.Info("Stopping worker pool")

	for _, worker := range p.workers {
		worker.Stop()
	}

	p.wg.Wait()
}

// Size returns the number of workers in the pool
func (p *Pool) Size() int {
	return len(p.workers)
}

// Errors
var (
	ErrQueueFull   = errors.New("queue is full")
	ErrQueueClosed = errors.New("queue is closed")
)
