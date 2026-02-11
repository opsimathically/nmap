import test from 'node:test';
import assert from 'node:assert';
import { NMAPReportParser } from '@src/classes/nmap/NMAPReportParser.class';

const sample_nmap_xml = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" start="1717171717" startstr="Sat Jun 1" version="7.94" xmloutputversion="1.05">
  <host>
    <status state="up" reason="syn-ack" />
    <address addr="127.0.0.1" addrtype="ipv4" />
    <hostnames>
      <hostname name="localhost" type="PTR" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64" />
        <service name="ssh" product="OpenSSH" version="9.6" />
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1717171720" timestr="Sat Jun 1" summary="Nmap done" elapsed="3.0" />
    <hosts up="1" down="0" total="1" />
  </runstats>
</nmaprun>`;

test('NMAPReportParser.parseXMLReport parses core host and runstats fields.', async () => {
  const parser = new NMAPReportParser();
  const parsed_report = await parser.parseXMLReport({ xml_report: sample_nmap_xml });

  assert.strictEqual(parsed_report.scanner, 'nmap');
  assert.strictEqual(parsed_report.version, '7.94');
  assert.strictEqual(parsed_report.hosts.length, 1);
  assert.strictEqual(parsed_report.hosts[0].addresses[0].addr, '127.0.0.1');
  assert.strictEqual(parsed_report.hosts[0].ports[0].portid, 22);
  assert.strictEqual(parsed_report.hosts[0].ports[0].service?.name, 'ssh');
  assert.strictEqual(parsed_report.runstats?.hosts?.total, 1);
});

test('NMAPReportParser.parseAndMapXMLReport maps parsed output to arbitrary objects.', async () => {
  const parser = new NMAPReportParser();
  const mapped_output = await parser.parseAndMapXMLReport({
    xml_report: sample_nmap_xml,
    map_report: ({ report }) => {
      return {
        open_ports: report.hosts.flatMap((host) =>
          host.ports
            .filter((port) => port.state?.state === 'open')
            .map((port) => ({
              host: host.addresses[0]?.addr ?? 'unknown',
              port: port.portid
            }))
        )
      };
    }
  });

  assert.deepStrictEqual(mapped_output, {
    open_ports: [{ host: '127.0.0.1', port: 22 }]
  });
});
