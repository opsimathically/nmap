import { NMAPProcessController } from '@src/index';

// This is just a simple test for checking keyboard interactivity works.  It's not integrated
// into the test suite as it requires human input.

(async function () {
  const nmap_controller = new NMAPProcessController();

  const scan_result = await nmap_controller.runScan({
    scan_request: {
      targets: ['scanme.nmap.org'],
      nmap_args: ['-sS'],
      sudo_mode: 'keyboard'
    }
  });

  console.log(scan_result.parsed_report?.hosts.length);
  debugger;
})();
