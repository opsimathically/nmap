import { XMLParser } from 'fast-xml-parser';

const nmap_xml_parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '',
  parseTagValue: false,
  trimValues: true
});

export type nmap_host_status_t = {
  state: string | null;
  reason: string | null;
};

export type nmap_host_address_t = {
  addr: string | null;
  addrtype: string | null;
  vendor: string | null;
};

export type nmap_port_state_t = {
  state: string | null;
  reason: string | null;
  reason_ttl: number | null;
};

export type nmap_port_service_t = {
  name: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
  method: string | null;
  conf: string | null;
  tunnel: string | null;
  ostype: string | null;
};

export type nmap_port_t = {
  protocol: string | null;
  portid: number | null;
  state: nmap_port_state_t | null;
  service: nmap_port_service_t | null;
};

export type nmap_host_t = {
  status: nmap_host_status_t | null;
  addresses: nmap_host_address_t[];
  hostnames: string[];
  ports: nmap_port_t[];
  raw: Record<string, any>;
};

export type nmap_runstats_finished_t = {
  time: number | null;
  timestr: string | null;
  summary: string | null;
  elapsed: number | null;
};

export type nmap_runstats_hosts_t = {
  up: number | null;
  down: number | null;
  total: number | null;
};

export type nmap_runstats_t = {
  finished: nmap_runstats_finished_t | null;
  hosts: nmap_runstats_hosts_t | null;
};

export type nmap_report_t = {
  scanner: string | null;
  args: string | null;
  start: number | null;
  startstr: string | null;
  version: string | null;
  xmloutputversion: string | null;
  hosts: nmap_host_t[];
  runstats: nmap_runstats_t | null;
  raw: Record<string, any>;
};

export class NMAPReportParserError extends Error {
  constructor(params: { message: string }) {
    super(params.message);
    this.name = 'NMAPReportParserError';
  }
}

type nmap_report_mapper_t<mapped_report_t> = (params: {
  report: nmap_report_t;
}) => mapped_report_t;

function EnsureArray<entry_t>(params: { value: entry_t | entry_t[] | null | undefined }): entry_t[] {
  if (params.value === undefined || params.value === null) {
    return [];
  }

  return Array.isArray(params.value) ? params.value : [params.value];
}

function StringOrNull(params: { value: unknown }): string | null {
  if (params.value === undefined || params.value === null) {
    return null;
  }

  return String(params.value);
}

function NumberOrNull(params: { value: unknown }): number | null {
  if (params.value === undefined || params.value === null || params.value === '') {
    return null;
  }

  const parsed_number = Number(params.value);
  return Number.isFinite(parsed_number) ? parsed_number : null;
}

function AttributeObject(params: { value: unknown }): Record<string, unknown> {
  if (params.value && typeof params.value === 'object') {
    return params.value as Record<string, unknown>;
  }

  return {};
}

function ParseHost(params: { host_value: unknown }): nmap_host_t {
  const host_object = AttributeObject({ value: params.host_value });
  const status_attributes = AttributeObject({ value: host_object.status });

  const addresses = EnsureArray({ value: host_object.address as any[] | any }).map(
    (address_value): nmap_host_address_t => {
      const attributes = AttributeObject({ value: address_value });
      return {
        addr: StringOrNull({ value: attributes.addr }),
        addrtype: StringOrNull({ value: attributes.addrtype }),
        vendor: StringOrNull({ value: attributes.vendor })
      };
    }
  );

  const hostnames_parent = AttributeObject({ value: host_object.hostnames });
  const hostnames = EnsureArray({
    value: hostnames_parent.hostname as Record<string, unknown> | Record<string, unknown>[]
  })
    .map((hostname_value) => {
      const attributes = AttributeObject({ value: hostname_value });
      return StringOrNull({ value: attributes.name });
    })
    .filter((hostname): hostname is string => hostname !== null);

  const ports_parent = AttributeObject({ value: host_object.ports });
  const ports = EnsureArray({
    value: ports_parent.port as Record<string, unknown> | Record<string, unknown>[]
  }).map((port_value): nmap_port_t => {
    const port_object = AttributeObject({ value: port_value });
    const port_attributes = port_object;
    const state_attributes = AttributeObject({ value: port_object.state });
    const service_attributes = AttributeObject({ value: port_object.service });

    const port_state: nmap_port_state_t | null =
      Object.keys(state_attributes).length === 0
        ? null
        : {
            state: StringOrNull({ value: state_attributes.state }),
            reason: StringOrNull({ value: state_attributes.reason }),
            reason_ttl: NumberOrNull({ value: state_attributes.reason_ttl })
          };

    const port_service: nmap_port_service_t | null =
      Object.keys(service_attributes).length === 0
        ? null
        : {
            name: StringOrNull({ value: service_attributes.name }),
            product: StringOrNull({ value: service_attributes.product }),
            version: StringOrNull({ value: service_attributes.version }),
            extrainfo: StringOrNull({ value: service_attributes.extrainfo }),
            method: StringOrNull({ value: service_attributes.method }),
            conf: StringOrNull({ value: service_attributes.conf }),
            tunnel: StringOrNull({ value: service_attributes.tunnel }),
            ostype: StringOrNull({ value: service_attributes.ostype })
          };

    return {
      protocol: StringOrNull({ value: port_attributes.protocol }),
      portid: NumberOrNull({ value: port_attributes.portid }),
      state: port_state,
      service: port_service
    };
  });

  return {
    status:
      Object.keys(status_attributes).length === 0
        ? null
        : {
            state: StringOrNull({ value: status_attributes.state }),
            reason: StringOrNull({ value: status_attributes.reason })
          },
    addresses,
    hostnames,
    ports,
    raw: host_object
  };
}

function ParseRunstats(params: { runstats_value: unknown }): nmap_runstats_t | null {
  const runstats_object = AttributeObject({ value: params.runstats_value });
  if (Object.keys(runstats_object).length === 0) {
    return null;
  }

  const finished_attributes = AttributeObject({ value: runstats_object.finished });
  const hosts_attributes = AttributeObject({ value: runstats_object.hosts });

  return {
    finished:
      Object.keys(finished_attributes).length === 0
        ? null
        : {
            time: NumberOrNull({ value: finished_attributes.time }),
            timestr: StringOrNull({ value: finished_attributes.timestr }),
            summary: StringOrNull({ value: finished_attributes.summary }),
            elapsed: NumberOrNull({ value: finished_attributes.elapsed })
          },
    hosts:
      Object.keys(hosts_attributes).length === 0
        ? null
        : {
            up: NumberOrNull({ value: hosts_attributes.up }),
            down: NumberOrNull({ value: hosts_attributes.down }),
            total: NumberOrNull({ value: hosts_attributes.total })
          }
  };
}

export class NMAPReportParser {
  async parseXMLReport(params: { xml_report: string }): Promise<nmap_report_t> {
    try {
      const parsed_xml = nmap_xml_parser.parse(params.xml_report) as Record<string, unknown>;

      const nmap_run = AttributeObject({ value: parsed_xml.nmaprun });
      const run_attributes = nmap_run;
      const hosts = EnsureArray({ value: nmap_run.host as unknown[] | unknown }).map(
        (host_value) => ParseHost({ host_value })
      );
      const runstats = ParseRunstats({ runstats_value: nmap_run.runstats });

      return {
        scanner: StringOrNull({ value: run_attributes.scanner }),
        args: StringOrNull({ value: run_attributes.args }),
        start: NumberOrNull({ value: run_attributes.start }),
        startstr: StringOrNull({ value: run_attributes.startstr }),
        version: StringOrNull({ value: run_attributes.version }),
        xmloutputversion: StringOrNull({ value: run_attributes.xmloutputversion }),
        hosts,
        runstats,
        raw: nmap_run
      };
    } catch (error) {
      const error_message =
        error instanceof Error ? error.message : 'Unknown XML parsing error.';

      throw new NMAPReportParserError({
        message: `Failed to parse nmap XML report: ${error_message}`
      });
    }
  }

  mapReport<mapped_report_t>(params: {
    report: nmap_report_t;
    map_report: nmap_report_mapper_t<mapped_report_t>;
  }): mapped_report_t {
    return params.map_report({ report: params.report });
  }

  async parseAndMapXMLReport<mapped_report_t>(params: {
    xml_report: string;
    map_report: nmap_report_mapper_t<mapped_report_t>;
  }): Promise<mapped_report_t> {
    const parsed_report = await this.parseXMLReport({ xml_report: params.xml_report });
    return this.mapReport({ report: parsed_report, map_report: params.map_report });
  }
}
