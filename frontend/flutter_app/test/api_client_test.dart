import 'dart:convert';
import 'dart:typed_data';

import 'package:cti_app/src/api/api_client.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'fakes.dart';

void main() {
  test('builds search queries with repeated severity parameters', () async {
    final log = <http.Request>[];
    final api = ApiClient(
      client: fakeBackend({'/api/v1/vulnerabilities': vulnerabilityPage}, log: log),
      baseUrl: 'http://api.test',
    );

    final page = await api.searchVulnerabilities(
      q: ' log4j ',
      severity: ['CRITICAL', 'HIGH'],
      inKev: true,
      page: 2,
    );

    expect(page.items.single.cveId, 'CVE-2021-44228');
    expect(page.items.single.inKev, isTrue);
    final uri = log.single.url;
    expect(uri.queryParametersAll['severity'], ['CRITICAL', 'HIGH']);
    expect(uri.queryParameters['q'], 'log4j');
    expect(uri.queryParameters['in_kev'], 'true');
    expect(uri.queryParameters['page'], '2');
  });

  test('turns problem details into ApiException', () async {
    final api = ApiClient(
      client: MockClient(
        (_) async => http.Response(
          jsonEncode({
            'status': 422,
            'detail': 'Request validation failed.',
            'code': 'validation_error',
            'errors': [
              {'msg': 'String should have at most 200 characters'},
            ],
          }),
          422,
        ),
      ),
      baseUrl: 'http://api.test',
    );

    expect(
      () => api.searchVulnerabilities(q: 'x'),
      throwsA(
        isA<ApiException>()
            .having((e) => e.status, 'status', 422)
            .having((e) => e.code, 'code', 'validation_error')
            .having((e) => e.message, 'message', contains('at most 200')),
      ),
    );
  });

  test('reports network failures without a status', () async {
    final api = ApiClient(
      client: MockClient((_) async => throw http.ClientException('refused')),
      baseUrl: 'http://api.test',
    );

    expect(
      () => api.stats(),
      throwsA(
        isA<ApiException>()
            .having((e) => e.isNetwork, 'isNetwork', isTrue)
            .having((e) => e.message, 'message', contains('http://api.test')),
      ),
    );
  });

  test('readiness body is parsed even with HTTP 503', () async {
    final api = ApiClient(
      client: MockClient(
        (_) async => http.Response(
          jsonEncode({
            'status': 'unavailable',
            'checks': {
              'database': {'status': 'unavailable'},
            },
          }),
          503,
        ),
      ),
      baseUrl: 'http://api.test',
    );
    final readiness = await api.readiness();
    expect(readiness.status, 'unavailable');
    expect(readiness.checks['database']!['status'], 'unavailable');
  });

  test('uploads manifests as multipart', () async {
    late http.BaseRequest seen;
    String? body;
    final api = ApiClient(
      client: MockClient((request) async {
        seen = request;
        body = request.body;
        return http.Response(jsonEncode(dependencyReport), 200);
      }),
      baseUrl: 'http://api.test',
    );
    final report = await api.analyzeDependencies(
      'requirements.txt',
      Uint8List.fromList(utf8.encode('flask==2.2.4\n')),
    );

    expect(seen.url.path, '/api/v1/dependencies/analyze');
    expect(seen.headers['content-type'], startsWith('multipart/form-data'));
    expect(body, contains('filename="requirements.txt"'));
    expect(report.findings.first.confidence, 'confirmed');
    expect(report.vulnerablePackages, 1);
  });
}
