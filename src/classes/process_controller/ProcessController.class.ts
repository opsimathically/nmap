import { spawn } from 'node:child_process';

export type process_run_options_t = {
  command: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeout_ms?: number;
  abort_signal?: AbortSignal;
  stdin_text?: string;
  stdin_from_parent?: boolean;
  mirror_stdout_to_parent?: boolean;
  mirror_stderr_to_parent?: boolean;
};

export type process_run_result_t = {
  command: string;
  args: string[];
  command_string: string;
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  aborted: boolean;
  duration_ms: number;
  spawn_error: string | null;
};

function QuoteCommandArg(params: { arg: string }): string {
  const requires_quotes = /\s|["'\\$`]/.test(params.arg);

  if (!requires_quotes) {
    return params.arg;
  }

  const escaped_arg = params.arg.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${escaped_arg}"`;
}

function BuildCommandString(params: { command: string; args: string[] }): string {
  return [params.command, ...params.args.map((arg) => QuoteCommandArg({ arg }))].join(
    ' '
  );
}

export class ProcessController {
  async runCommand(params: {
    process_run_options: process_run_options_t;
  }): Promise<process_run_result_t> {
    const {
      command,
      args = [],
      cwd,
      env,
      timeout_ms,
      abort_signal,
      stdin_text,
      stdin_from_parent = false,
      mirror_stdout_to_parent = false,
      mirror_stderr_to_parent = false
    } = params.process_run_options;

    const started_at = Date.now();

    return await new Promise<process_run_result_t>((resolve) => {
      let stdout = '';
      let stderr = '';
      let timed_out = false;
      let aborted = false;
      let spawn_error: string | null = null;
      let timeout_id: NodeJS.Timeout | undefined;

      const stdio: ['pipe' | 'inherit', 'pipe', 'pipe'] = [
        stdin_from_parent ? 'inherit' : 'pipe',
        'pipe',
        'pipe'
      ];

      const child_process_instance = spawn(command, args, {
        cwd,
        env,
        shell: false,
        stdio
      });

      const on_abort = (): void => {
        aborted = true;
        child_process_instance.kill('SIGTERM');
      };

      if (abort_signal) {
        abort_signal.addEventListener('abort', on_abort, { once: true });
      }

      if (typeof timeout_ms === 'number' && timeout_ms > 0) {
        timeout_id = setTimeout(() => {
          timed_out = true;
          child_process_instance.kill('SIGTERM');
        }, timeout_ms);
      }

      if (child_process_instance.stdout) {
        child_process_instance.stdout.on('data', (chunk: Buffer | string) => {
          const chunk_string = String(chunk);
          stdout += chunk_string;
          if (mirror_stdout_to_parent) {
            process.stdout.write(chunk_string);
          }
        });
      }

      if (child_process_instance.stderr) {
        child_process_instance.stderr.on('data', (chunk: Buffer | string) => {
          const chunk_string = String(chunk);
          stderr += chunk_string;
          if (mirror_stderr_to_parent) {
            process.stderr.write(chunk_string);
          }
        });
      }

      child_process_instance.on('error', (error: Error) => {
        spawn_error = error.message;
      });

      if (!stdin_from_parent && child_process_instance.stdin) {
        if (typeof stdin_text === 'string') {
          child_process_instance.stdin.write(stdin_text);
        }
        child_process_instance.stdin.end();
      }

      child_process_instance.on('close', (exit_code, signal) => {
        if (timeout_id) {
          clearTimeout(timeout_id);
        }
        if (abort_signal) {
          abort_signal.removeEventListener('abort', on_abort);
        }

        resolve({
          command,
          args,
          command_string: BuildCommandString({ command, args }),
          exit_code,
          signal,
          stdout,
          stderr,
          timed_out,
          aborted,
          duration_ms: Date.now() - started_at,
          spawn_error
        });
      });
    });
  }
}
