import test from 'node:test';
import assert from 'node:assert';
import {
  NMAPProcessController,
  NMAPScanError,
  NMAPSudoError
} from '@src/classes/nmap/NMAPProcessController.class';
import type {
  process_run_options_t,
  process_run_result_t
} from '@src/classes/process_controller/ProcessController.class';

const sample_nmap_xml = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap 127.0.0.1" version="7.94">
  <host>
    <status state="up" reason="syn-ack" />
    <address addr="127.0.0.1" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64" />
        <service name="http" />
      </port>
    </ports>
  </host>
</nmaprun>`;

class MockNMAPProcessController extends NMAPProcessController {
  private next_run_result: process_run_result_t = {
    command: 'nmap',
    args: ['-oX', '-', '127.0.0.1'],
    command_string: 'nmap -oX - 127.0.0.1',
    exit_code: 0,
    signal: null,
    stdout: sample_nmap_xml,
    stderr: '',
    timed_out: false,
    aborted: false,
    duration_ms: 10,
    spawn_error: null
  };

  setNextRunResult(params: { process_result: process_run_result_t }): void {
    this.next_run_result = params.process_result;
  }

  override async runCommand(params: {
    process_run_options: process_run_options_t;
  }): Promise<process_run_result_t> {
    void params;
    return this.next_run_result;
  }
}

test('NMAPProcessController.buildScanCommand enforces xml stdout mode and target list.', () => {
  const controller = new NMAPProcessController();
  const built_command = controller.buildScanCommand({
    scan_request: {
      targets: ['127.0.0.1'],
      nmap_args: ['-sV', '-oX', '/tmp/out.xml'],
      sudo_mode: 'none'
    }
  });

  assert.strictEqual(built_command.command, 'nmap');
  assert.deepStrictEqual(built_command.args, ['-sV', '-oX', '-', '127.0.0.1']);
});

test('NMAPProcessController.buildScanCommand sets keyboard sudo behavior.', () => {
  const controller = new NMAPProcessController();
  const built_command = controller.buildScanCommand({
    scan_request: {
      targets: ['scanme.nmap.org'],
      sudo_mode: 'keyboard'
    }
  });

  assert.strictEqual(built_command.command, 'sudo');
  assert.deepStrictEqual(built_command.args.slice(0, 5), [
    '-S',
    '-p',
    '[sudo] password: ',
    '--',
    'nmap'
  ]);
  assert.strictEqual(built_command.process_run_options.stdin_from_parent, true);
});

test('NMAPProcessController.buildScanCommand requires password for programmatic sudo.', () => {
  const controller = new NMAPProcessController();
  assert.throws(
    () =>
      controller.buildScanCommand({
        scan_request: {
          targets: ['127.0.0.1'],
          sudo_mode: 'programmatic'
        }
      }),
    (error: unknown) => {
      assert(error instanceof NMAPScanError);
      return error.error_code === 'missing_sudo_password';
    }
  );
});

test('NMAPProcessController.runScan returns parsed report and structured metadata.', async () => {
  const controller = new MockNMAPProcessController();
  const result = await controller.runScan({
    scan_request: {
      targets: ['127.0.0.1'],
      sudo_mode: 'none'
    }
  });

  assert.strictEqual(result.executed_command.sudo_mode, 'none');
  assert.strictEqual(result.exit_code, 0);
  assert.strictEqual(result.parsed_report?.hosts[0].ports[0].service?.name, 'http');
});

test('NMAPProcessController.runScan detects sudo auth failures.', async () => {
  const controller = new MockNMAPProcessController();
  controller.setNextRunResult({
    process_result: {
      command: 'sudo',
      args: ['-S', '-p', '', '--', 'nmap', '-oX', '-', '127.0.0.1'],
      command_string: 'sudo -S -p "" -- nmap -oX - 127.0.0.1',
      exit_code: 1,
      signal: null,
      stdout: '',
      stderr: 'sudo: 1 incorrect password attempt\nSorry, try again.\n',
      timed_out: false,
      aborted: false,
      duration_ms: 15,
      spawn_error: null
    }
  });

  await assert.rejects(
    async () =>
      await controller.runScan({
        scan_request: {
          targets: ['127.0.0.1'],
          sudo_mode: 'programmatic',
          sudo_password: 'not-real'
        }
      }),
    (error: unknown) => {
      assert(error instanceof NMAPSudoError);
      return error.error_code === 'incorrect_password';
    }
  );
});
