import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

/// A MockClient serving canned JSON per path, recording requests.
MockClient fakeBackend(Map<String, Object> routes, {List<http.Request>? log}) {
  return MockClient((request) async {
    log?.add(request);
    final body = routes[request.url.path];
    if (body == null) {
      return http.Response(
        jsonEncode({'title': 'Not Found', 'status': 404, 'detail': 'missing', 'code': 'not_found'}),
        404,
        headers: {'content-type': 'application/problem+json'},
      );
    }
    return http.Response(jsonEncode(body), 200, headers: {'content-type': 'application/json'});
  });
}

const stats = {
  'vulnerabilities': 2,
  'kev_entries': 3,
  'kev_with_cve_record': 1,
  'attack_techniques': 7,
  'capec_patterns': 3,
  'advisories': 1,
  'document_chunks': 12,
  'embedded_chunks': 12,
  'by_severity': [
    {'key': 'CRITICAL', 'count': 1},
    {'key': 'HIGH', 'count': 1},
  ],
  'top_cwes': [
    {'key': 'CWE-502', 'label': 'Deserialization', 'count': 1},
  ],
  'recent_kev': [
    {
      'cve_id': 'CVE-2023-4966',
      'vendor_project': 'Citrix',
      'product': 'NetScaler',
      'vulnerability_name': 'Citrix Bleed',
      'date_added': '2023-10-18',
      'known_ransomware_use': 'Known',
      'has_cve_record': false,
      'cwes': ['CWE-119'],
    },
  ],
};

const vulnerabilityPage = {
  'items': [
    {
      'cve_id': 'CVE-2021-44228',
      'state': 'PUBLISHED',
      'title': 'Log4Shell',
      'description_snippet': 'Apache Log4j2 JNDI features',
      'severity': 'CRITICAL',
      'cvss_base_score': 10.0,
      'in_kev': true,
      'cwes': ['CWE-502'],
    },
  ],
  'page': 1,
  'page_size': 20,
  'total': 1,
};

const chatAnswer = {
  'question': 'Is Log4Shell exploited?',
  'answer': 'Source facts: Log4j2 is in CISA KEV [E1].',
  'mode': 'generated',
  'grounded': true,
  'citations': [
    {
      'id': 'E1',
      'entity_type': 'vulnerability',
      'entity_id': 'CVE-2021-44228',
      'cve_id': 'CVE-2021-44228',
      'title': 'CVE-2021-44228: Log4Shell',
      'source_name': 'CVE Program record + CISA KEV',
      'source_url': 'https://www.cve.org/CVERecord?id=CVE-2021-44228',
      'snippet': 'Apache Log4j2 JNDI features',
    },
  ],
  'cve_ids': ['CVE-2021-44228'],
  'facts': [
    {
      'cve_id': 'CVE-2021-44228',
      'record_url': 'https://www.cve.org/CVERecord?id=CVE-2021-44228',
      'severity': 'CRITICAL',
      'cvss_base_score': 10.0,
      'cvss_version': '3.1',
      'cvss_provider': 'CISA-ADP',
      'in_kev': true,
      'kev_date_added': '2021-12-10',
      'known_ransomware_use': 'Known',
      'cwes': ['CWE-502'],
    },
  ],
  'warnings': <String>[],
  'model': {'provider': 'mock', 'name': 'mock-deterministic'},
  'retrieval': <String, Object>{},
  'prompt_version': 'rag-v1',
  'latency_ms': 12.0,
  'disclaimer': 'Verify facts against the linked records.',
};

const dependencyReport = {
  'filename': 'requirements.txt',
  'sha256': 'abc',
  'format': 'requirements.txt',
  'ecosystem': 'PyPI',
  'dependency_count': 2,
  'checked_count': 1,
  'unpinned_count': 1,
  'vulnerable_packages': 1,
  'findings': [
    {
      'package': 'flask',
      'ecosystem': 'PyPI',
      'version': '2.2.4',
      'location': 'line 1',
      'confidence': 'confirmed',
      'reason': '2.2.4 is inside an affected range',
      'advisory_id': 'GHSA-m2qf-hxjv-5gpq',
      'cve_ids': ['CVE-2023-30861'],
      'severity': 'HIGH',
      'summary': 'Flask cookie disclosure',
      'fixed_versions': ['2.2.5', '2.3.2'],
      'in_kev': false,
      'source': 'OSV advisory (local export)',
      'references': ['https://osv.dev/vulnerability/GHSA-m2qf-hxjv-5gpq'],
    },
    {
      'package': 'django',
      'ecosystem': 'PyPI',
      'specifier': '>=4.2',
      'location': 'line 2',
      'confidence': 'uncertain',
      'reason': 'version not pinned',
      'advisory_id': 'GHSA-xxxx',
      'cve_ids': <String>[],
      'severity': 'MEDIUM',
      'fixed_versions': <String>[],
      'in_kev': false,
      'source': 'OSV advisory (local export)',
      'references': <String>[],
    },
  ],
  'not_checked': [
    {'entry': '-r other.txt', 'reason': 'included files are not read'},
  ],
  'warnings': <String>[],
  'summary': <String, Object>{},
  'sources': <String>[],
};
