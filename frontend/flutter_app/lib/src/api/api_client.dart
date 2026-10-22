import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../config.dart';
import 'models.dart';

/// An error returned by the API (RFC 9457 problem details) or a transport failure.
class ApiException implements Exception {
  ApiException(this.message, {this.status, this.code});

  final String message;
  final int? status;
  final String? code;

  bool get isNetwork => status == null;

  @override
  String toString() => message;
}

class ApiClient {
  ApiClient({http.Client? client, String? baseUrl})
    : _client = client ?? http.Client(),
      baseUrl = baseUrl ?? resolveApiBaseUrl();

  final http.Client _client;
  final String baseUrl;

  static const _timeout = Duration(seconds: 20);
  static const _chatTimeout = Duration(seconds: 150);

  Uri _uri(String path, [Map<String, dynamic>? query]) {
    final params = <String, dynamic>{};
    query?.forEach((key, value) {
      if (value == null) return;
      if (value is List) {
        if (value.isNotEmpty) params[key] = value.map((v) => '$v').toList();
      } else if ('$value'.isNotEmpty) {
        params[key] = '$value';
      }
    });
    final base = Uri.parse('$baseUrl$path');
    return params.isEmpty ? base : base.replace(queryParameters: params);
  }

  /// Sends a request and returns the decoded JSON body.
  ///
  /// Non-2xx responses become [ApiException] with the problem-details message, unless
  /// [acceptErrorBody] is set (readiness returns a useful body with 503).
  Future<Object?> _request(
    Future<http.Response> request,
    Duration timeout, {
    bool acceptErrorBody = false,
  }) async {
    final http.Response response;
    try {
      response = await request.timeout(timeout);
    } on TimeoutException {
      throw ApiException('The server did not respond in time.');
    } catch (_) {
      throw ApiException('Cannot reach the API at $baseUrl. Is the backend running?');
    }
    Object? body;
    try {
      body = response.body.isEmpty ? null : jsonDecode(utf8.decode(response.bodyBytes));
    } on FormatException {
      body = null;
    }
    final ok = response.statusCode >= 200 && response.statusCode < 300;
    if (ok || (acceptErrorBody && body is Map)) return body;
    final problem = body is Map ? body.cast<String, dynamic>() : <String, dynamic>{};
    var message = problem['detail'] is String
        ? problem['detail'] as String
        : 'Request failed (HTTP ${response.statusCode}).';
    final errors = problem['errors'];
    if (errors is List && errors.isNotEmpty && errors.first is Map) {
      final first = (errors.first as Map).cast<String, dynamic>();
      message = '$message ${first['msg'] ?? ''}'.trim();
    }
    throw ApiException(message, status: response.statusCode, code: problem['code'] as String?);
  }

  Map<String, dynamic> _asMap(Object? body) {
    if (body is Map) return body.cast<String, dynamic>();
    throw ApiException('Unexpected response from the API.');
  }

  Future<Map<String, dynamic>> _get(String path, [Map<String, dynamic>? query]) async =>
      _asMap(await _request(_client.get(_uri('$apiPrefix$path', query)), _timeout));

  Future<Stats> stats() async => Stats.fromJson(await _get('/stats'));

  Future<List<SourceStatus>> sources() async {
    final body = await _request(_client.get(_uri('$apiPrefix/sources')), _timeout);
    return (body is List ? body : const [])
        .whereType<Map>()
        .map((m) => SourceStatus.fromJson(m.cast<String, dynamic>()))
        .toList();
  }

  Future<Readiness> readiness() async => Readiness.fromJson(
    _asMap(
      await _request(_client.get(_uri('$apiPrefix/health/ready')), _timeout, acceptErrorBody: true),
    ),
  );

  Future<ApiPage<VulnerabilitySummary>> searchVulnerabilities({
    String? q,
    List<String> severity = const [],
    bool? inKev,
    String sort = 'relevance',
    int page = 1,
    int pageSize = 20,
  }) async => ApiPage.fromJson(
    await _get('/vulnerabilities', {
      'q': q?.trim(),
      'severity': severity,
      'in_kev': inKev,
      'sort': sort,
      'page': page,
      'page_size': pageSize,
    }),
    VulnerabilitySummary.fromJson,
  );

  Future<SearchResult> semanticSearch(String q, {int k = 15, bool? inKev}) async =>
      SearchResult.fromJson(await _get('/search', {'q': q.trim(), 'k': k, 'in_kev': inKev}));

  Future<VulnerabilityDetail> vulnerability(String cveId) async =>
      VulnerabilityDetail.fromJson(await _get('/vulnerabilities/${Uri.encodeComponent(cveId)}'));

  Future<Correlation> correlations(String cveId) async => Correlation.fromJson(
    await _get('/vulnerabilities/${Uri.encodeComponent(cveId)}/correlations'),
  );

  Future<ApiPage<KevItem>> kev({String? q, String? ransomware, int page = 1}) async =>
      ApiPage.fromJson(
        await _get('/kev', {'q': q?.trim(), 'ransomware': ransomware, 'page': page}),
        KevItem.fromJson,
      );

  Future<ChatAnswer> ask(String question) async => ChatAnswer.fromJson(
    _asMap(
      await _request(
        _client.post(
          _uri('$apiPrefix/chat'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'question': question}),
        ),
        _chatTimeout,
      ),
    ),
  );

  Future<DependencyReport> analyzeDependencies(String filename, Uint8List bytes) async {
    final request = http.MultipartRequest('POST', _uri('$apiPrefix/dependencies/analyze'))
      ..files.add(http.MultipartFile.fromBytes('file', bytes, filename: filename));
    final streamed = _client.send(request).then(http.Response.fromStream);
    return DependencyReport.fromJson(_asMap(await _request(streamed, _timeout)));
  }
}
