import test from 'node:test';
import assert from 'node:assert';
import { ProcessController } from '@src/classes/process_controller/ProcessController.class';

test('ProcessController.runCommand captures stdout/stderr and exit metadata.', async () => {
  const process_controller = new ProcessController();
  const process_result = await process_controller.runCommand({
    process_run_options: {
      command: 'bash',
      args: ['-lc', 'printf "ok"; printf "warn" >&2']
    }
  });

  assert.strictEqual(process_result.stdout, 'ok');
  assert.strictEqual(process_result.stderr, 'warn');
  assert.strictEqual(process_result.exit_code, 0);
});

test('ProcessController.runCommand enforces timeout.', async () => {
  const process_controller = new ProcessController();
  const process_result = await process_controller.runCommand({
    process_run_options: {
      command: 'bash',
      args: ['-lc', 'sleep 2'],
      timeout_ms: 50
    }
  });

  assert.strictEqual(process_result.timed_out, true);
  assert.strictEqual(process_result.aborted, false);
});

test('ProcessController.runCommand handles abort signal cancellation.', async () => {
  const process_controller = new ProcessController();
  const abort_controller = new AbortController();

  setTimeout(() => {
    abort_controller.abort();
  }, 50);

  const process_result = await process_controller.runCommand({
    process_run_options: {
      command: 'bash',
      args: ['-lc', 'sleep 2'],
      abort_signal: abort_controller.signal
    }
  });

  assert.strictEqual(process_result.aborted, true);
});
