# NMAP

TypeScript wrapper for driving Linux `nmap` scans, capturing XML output, and parsing into
typed objects.

## Features

- Programmatically run `nmap` with arbitrary arguments and target lists.
- Enforce XML stdout mode (`-oX -`) and return raw XML.
- Parse XML reports into strongly typed objects (via `fast-xml-parser`).
- Map parsed reports to arbitrary app-specific shapes.
- Optional `sudo` modes for privileged scans:
  - `none`
  - `keyboard` (interactive terminal password input)
  - `programmatic` (password piped via `sudo -S`)
- Timeout and abort-signal support.

## Install

```bash
npm install @opsimathically/nmap
```

## Basic scan

```typescript
import { NMAPProcessController } from '@opsimathically/nmap';

const nmap_controller = new NMAPProcessController();

const scan_result = await nmap_controller.runScan({
  scan_request: {
    targets: ['127.0.0.1'],
    nmap_args: ['-sV'],
    sudo_mode: 'none'
  }
});

console.log(scan_result.exit_code);
console.log(scan_result.stdout_xml);
console.log(scan_result.parsed_report?.hosts);
```

## Keyboard sudo mode

```typescript
import { NMAPProcessController } from '@opsimathically/nmap';

const nmap_controller = new NMAPProcessController();

const scan_result = await nmap_controller.runScan({
  scan_request: {
    targets: ['scanme.nmap.org'],
    nmap_args: ['-sS'],
    sudo_mode: 'keyboard'
  }
});

console.log(scan_result.parsed_report?.hosts.length);
```

## Programmatic sudo mode

```typescript
import { NMAPProcessController } from '@opsimathically/nmap';

const nmap_controller = new NMAPProcessController();

const scan_result = await nmap_controller.runScan({
  scan_request: {
    targets: ['scanme.nmap.org'],
    nmap_args: ['-sS'],
    sudo_mode: 'programmatic',
    sudo_password: process.env.NMAP_SUDO_PASSWORD
  }
});

console.log(scan_result.stderr);
```

## Map parsed XML into custom objects

```typescript
import { NMAPProcessController } from '@opsimathically/nmap';

const nmap_controller = new NMAPProcessController();

const mapped_result = await nmap_controller.runScanAndMap({
  scan_request: {
    targets: ['127.0.0.1'],
    nmap_args: ['-sV'],
    sudo_mode: 'none'
  },
  map_report: ({ report }) => {
    return report.hosts.map((host) => ({
      host: host.addresses[0]?.addr,
      open_ports: host.ports
        .filter((port) => port.state?.state === 'open')
        .map((port) => port.portid)
    }));
  }
});

console.log(mapped_result.mapped_report);
```

## Build from source

```bash
npm install
npm run build
```

## Test

```bash
npm test
```
