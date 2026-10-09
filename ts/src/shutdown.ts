import type { Server } from "node:http";

/// Upper bound on how long in-flight requests are given to finish after a
/// shutdown signal. A cap, not a delay: shutdown completes as soon as the last
/// request drains. Matches the Go and Rust implementations.
export const SHUTDOWN_TIMEOUT_MS = 30_000;

export interface ShutdownOptions {
  timeoutMs?: number;
  log?: (msg: string) => void;
  error?: (msg: string) => void;
  exit?: (code: number) => void;
}

/**
 * Builds the signal handler for a server.
 *
 * Extracted from index.ts so it can be tested: shutdown behaviour is invisible
 * to the integration suite, which asserts HTTP status codes and cannot observe
 * process lifecycle.
 *
 * `server.close()` already does most of the work: since Node 19 it releases
 * idle keep-alive connections as well as waiting for active requests, so the
 * happy path needs no help. What it lacks is an upper bound — a request that
 * never completes would block exit forever, with no equivalent of Go's or
 * Rust's 30s cap.
 */
export function createShutdown(server: Server, options: ShutdownOptions = {}): (signal: string) => void {
  const timeoutMs = options.timeoutMs ?? SHUTDOWN_TIMEOUT_MS;
  const log = options.log ?? ((m: string) => console.log(m));
  const error = options.error ?? ((m: string) => console.error(m));
  const exit = options.exit ?? ((c: number) => process.exit(c));

  let shuttingDown = false;

  return function shutdown(signal: string): void {
    // A second SIGTERM (docker stop followed by an impatient operator) must not
    // re-enter and close an already-closing server.
    if (shuttingDown) return;
    shuttingDown = true;

    log(`received ${signal}, shutting down...`);

    const deadline = setTimeout(() => {
      error("drain deadline exceeded, forcing close");
      server.closeAllConnections();
      exit(1);
    }, timeoutMs);
    // Do not let the deadline itself keep the process alive once draining is
    // done — otherwise every shutdown would stall for the full timeout.
    deadline.unref();

    server.close(() => {
      clearTimeout(deadline);
      log("server closed");
      exit(0);
    });
  };
}
