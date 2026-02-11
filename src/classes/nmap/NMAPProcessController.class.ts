import {
  ProcessController,
  type process_run_options_t,
  type process_run_result_t
} from '@src/classes/process_controller/ProcessController.class';
import {
  NMAPReportParser,
  type nmap_report_t
} from '@src/classes/nmap/NMAPReportParser.class';

export type nmap_sudo_mode_t = 'none' | 'keyboard' | 'programmatic';

export type nmap_scan_request_t = {
  targets: string[];
  nmap_args?: string[];
  sudo_mode?: nmap_sudo_mode_t;
  sudo_password?: string;
  timeout_ms?: number;
  abort_signal?: AbortSignal;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  parse_xml?: boolean;
  nmap_binary_path?: string;
  sudo_binary_path?: string;
};

export type nmap_executed_command_t = {
  command: string;
  args: string[];
  command_string: string;
  sudo_mode: nmap_sudo_mode_t;
};

export type nmap_scan_result_t = {
  executed_command: nmap_executed_command_t;
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  stdout_xml: string;
  parsed_report: nmap_report_t | null;
  stderr: string;
  duration_ms: number;
  timed_out: boolean;
  aborted: boolean;
  spawn_error: string | null;
};

export type nmap_mapped_scan_result_t<mapped_report_t> = nmap_scan_result_t & {
  mapped_report: mapped_report_t | null;
};

type nmap_sudo_error_code_t =
  | 'incorrect_password'
  | 'permission_denied'
  | 'sudo_not_found'
  | 'tty_required'
  | 'password_required';

type nmap_built_command_t = {
  command: string;
  args: string[];
  sudo_mode: nmap_sudo_mode_t;
  process_run_options: process_run_options_t;
};

export class NMAPSudoError extends Error {
  public readonly error_code: nmap_sudo_error_code_t;
  public readonly stderr: string;

  constructor(params: {
    message: string;
    error_code: nmap_sudo_error_code_t;
    stderr: string;
  }) {
    super(params.message);
    this.name = 'NMAPSudoError';
    this.error_code = params.error_code;
    this.stderr = params.stderr;
  }
}

export class NMAPScanError extends Error {
  public readonly error_code: string;

  constructor(params: { message: string; error_code: string }) {
    super(params.message);
    this.name = 'NMAPScanError';
    this.error_code = params.error_code;
  }
}

function FilterNmapArgs(params: { nmap_args: string[] }): string[] {
  const filtered_args: string[] = [];

  for (let arg_index = 0; arg_index < params.nmap_args.length; arg_index += 1) {
    const current_arg = params.nmap_args[arg_index];

    if (current_arg === '-oX' || current_arg === '-oA') {
      arg_index += 1;
      continue;
    }

    if (current_arg.startsWith('-oX') || current_arg.startsWith('-oA')) {
      continue;
    }

    filtered_args.push(current_arg);
  }

  return filtered_args;
}

function DetectSudoErrorCode(params: {
  stderr: string;
  spawn_error: string | null;
}): nmap_sudo_error_code_t | null {
  const combined_message = `${params.stderr}\n${params.spawn_error ?? ''}`.toLowerCase();

  if (
    combined_message.includes('sudo: command not found') ||
    combined_message.includes('enoent')
  ) {
    return 'sudo_not_found';
  }

  if (
    combined_message.includes('no tty present') ||
    combined_message.includes('a terminal is required')
  ) {
    return 'tty_required';
  }

  if (combined_message.includes('sorry, try again')) {
    return 'incorrect_password';
  }

  if (combined_message.includes('a password is required')) {
    return 'password_required';
  }

  if (
    combined_message.includes('is not in the sudoers file') ||
    combined_message.includes('permission denied')
  ) {
    return 'permission_denied';
  }

  return null;
}

function SudoErrorMessage(params: { error_code: nmap_sudo_error_code_t }): string {
  if (params.error_code === 'incorrect_password') {
    return 'sudo authentication failed: incorrect password.';
  }

  if (params.error_code === 'permission_denied') {
    return 'sudo permission denied for this user.';
  }

  if (params.error_code === 'sudo_not_found') {
    return 'sudo is not installed or not available in PATH.';
  }

  if (params.error_code === 'tty_required') {
    return 'sudo requires a TTY. Use keyboard mode from an interactive terminal.';
  }

  return 'sudo requires a password but none was provided.';
}

export class NMAPProcessController extends ProcessController {
  protected readonly report_parser: NMAPReportParser;

  constructor(params?: { report_parser?: NMAPReportParser }) {
    super();
    this.report_parser = params?.report_parser ?? new NMAPReportParser();
  }

  buildScanCommand(params: { scan_request: nmap_scan_request_t }): nmap_built_command_t {
    const {
      targets,
      nmap_args = [],
      sudo_mode = 'none',
      sudo_password,
      timeout_ms,
      abort_signal,
      cwd,
      env,
      nmap_binary_path = 'nmap',
      sudo_binary_path = 'sudo'
    } = params.scan_request;

    if (!Array.isArray(targets) || targets.length === 0) {
      throw new NMAPScanError({
        message: 'At least one nmap target is required.',
        error_code: 'invalid_targets'
      });
    }

    if (sudo_mode === 'programmatic' && !sudo_password) {
      throw new NMAPScanError({
        message: 'sudo_password is required when sudo_mode is programmatic.',
        error_code: 'missing_sudo_password'
      });
    }

    const filtered_nmap_args = FilterNmapArgs({ nmap_args });
    const normalized_nmap_args = [...filtered_nmap_args, '-oX', '-', ...targets];

    if (sudo_mode === 'none') {
      const process_run_options: process_run_options_t = {
        command: nmap_binary_path,
        args: normalized_nmap_args,
        timeout_ms,
        abort_signal,
        cwd,
        env
      };

      return {
        command: nmap_binary_path,
        args: normalized_nmap_args,
        sudo_mode,
        process_run_options
      };
    }

    if (sudo_mode === 'keyboard') {
      const sudo_args = ['-S', '-p', '[sudo] password: ', '--', nmap_binary_path, ...normalized_nmap_args];
      const process_run_options: process_run_options_t = {
        command: sudo_binary_path,
        args: sudo_args,
        timeout_ms,
        abort_signal,
        cwd,
        env,
        stdin_from_parent: true,
        mirror_stderr_to_parent: true
      };

      return {
        command: sudo_binary_path,
        args: sudo_args,
        sudo_mode,
        process_run_options
      };
    }

    const sudo_args = ['-S', '-p', '', '--', nmap_binary_path, ...normalized_nmap_args];
    const process_run_options: process_run_options_t = {
      command: sudo_binary_path,
      args: sudo_args,
      timeout_ms,
      abort_signal,
      cwd,
      env,
      stdin_text: `${sudo_password ?? ''}\n`
    };

    return {
      command: sudo_binary_path,
      args: sudo_args,
      sudo_mode,
      process_run_options
    };
  }

  async runScan(params: { scan_request: nmap_scan_request_t }): Promise<nmap_scan_result_t> {
    const built_command = this.buildScanCommand({ scan_request: params.scan_request });
    const run_result = await this.runCommand({
      process_run_options: built_command.process_run_options
    });

    const sudo_error_code =
      built_command.sudo_mode === 'none'
        ? null
        : DetectSudoErrorCode({
            stderr: run_result.stderr,
            spawn_error: run_result.spawn_error
          });

    if (sudo_error_code) {
      throw new NMAPSudoError({
        message: SudoErrorMessage({ error_code: sudo_error_code }),
        error_code: sudo_error_code,
        stderr: run_result.stderr
      });
    }

    if (run_result.timed_out) {
      throw new NMAPScanError({
        message: 'nmap scan timed out before completion.',
        error_code: 'scan_timeout'
      });
    }

    if (run_result.aborted) {
      throw new NMAPScanError({
        message: 'nmap scan was aborted.',
        error_code: 'scan_aborted'
      });
    }

    if (run_result.spawn_error) {
      throw new NMAPScanError({
        message: `Failed to start nmap process: ${run_result.spawn_error}`,
        error_code: 'spawn_error'
      });
    }

    const should_parse_xml = params.scan_request.parse_xml ?? true;
    const stdout_xml = run_result.stdout;
    const parsed_report =
      should_parse_xml && stdout_xml.trim().length > 0
        ? await this.report_parser.parseXMLReport({ xml_report: stdout_xml })
        : null;

    return {
      executed_command: {
        command: run_result.command,
        args: run_result.args,
        command_string: run_result.command_string,
        sudo_mode: built_command.sudo_mode
      },
      exit_code: run_result.exit_code,
      signal: run_result.signal,
      stdout_xml,
      parsed_report,
      stderr: run_result.stderr,
      duration_ms: run_result.duration_ms,
      timed_out: run_result.timed_out,
      aborted: run_result.aborted,
      spawn_error: run_result.spawn_error
    };
  }

  async runScanAndMap<mapped_report_t>(params: {
    scan_request: nmap_scan_request_t;
    map_report: (params: { report: nmap_report_t }) => mapped_report_t;
  }): Promise<nmap_mapped_scan_result_t<mapped_report_t>> {
    const scan_result = await this.runScan({ scan_request: params.scan_request });

    return {
      ...scan_result,
      mapped_report: scan_result.parsed_report
        ? this.report_parser.mapReport({
            report: scan_result.parsed_report,
            map_report: params.map_report
          })
        : null
    };
  }

  // Supports deterministic unit testing without shelling out to nmap.
  async runCommand(params: {
    process_run_options: process_run_options_t;
  }): Promise<process_run_result_t> {
    return await super.runCommand(params);
  }
}
