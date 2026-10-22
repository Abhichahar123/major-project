// Typed views of the backend JSON. Parsing is defensive: missing optional fields become
// null or empty rather than throwing, so a newer backend does not break the app.

String? _s(Object? v) => v is String ? v : null;
double? _d(Object? v) => v is num ? v.toDouble() : null;
int _i(Object? v) => v is num ? v.toInt() : 0;
bool _b(Object? v) => v == true;
List<String> _strings(Object? v) => v is List ? v.whereType<String>().toList() : const <String>[];
List<Map<String, dynamic>> _maps(Object? v) =>
    v is List ? v.whereType<Map>().map((m) => m.cast<String, dynamic>()).toList() : const [];
Map<String, dynamic> _map(Object? v) => v is Map ? v.cast<String, dynamic>() : <String, dynamic>{};

class ApiPage<T> {
  ApiPage({required this.items, required this.page, required this.pageSize, required this.total});

  final List<T> items;
  final int page;
  final int pageSize;
  final int total;

  bool get hasMore => page * pageSize < total;

  static ApiPage<T> fromJson<T>(Map<String, dynamic> json, T Function(Map<String, dynamic>) item) =>
      ApiPage(
        items: _maps(json['items']).map(item).toList(),
        page: _i(json['page']),
        pageSize: _i(json['page_size']),
        total: _i(json['total']),
      );
}

class VulnerabilitySummary {
  VulnerabilitySummary.fromJson(Map<String, dynamic> j)
    : cveId = _s(j['cve_id']) ?? '',
      title = _s(j['title']),
      snippet = _s(j['description_snippet']),
      severity = _s(j['severity']),
      cvss = _d(j['cvss_base_score']),
      cvssVersion = _s(j['cvss_version']),
      published = _s(j['published_at']),
      inKev = _b(j['in_kev']),
      cwes = _strings(j['cwes']);

  final String cveId;
  final String? title;
  final String? snippet;
  final String? severity;
  final double? cvss;
  final String? cvssVersion;
  final String? published;
  final bool inKev;
  final List<String> cwes;
}

class KevItem {
  KevItem.fromJson(Map<String, dynamic> j)
    : cveId = _s(j['cve_id']) ?? '',
      vendor = _s(j['vendor_project']) ?? '',
      product = _s(j['product']) ?? '',
      name = _s(j['vulnerability_name']) ?? '',
      dateAdded = _s(j['date_added']) ?? '',
      dueDate = _s(j['due_date']),
      ransomware = _s(j['known_ransomware_use']) ?? 'Unknown',
      hasRecord = _b(j['has_cve_record']),
      severity = _s(j['severity']),
      cvss = _d(j['cvss_base_score']);

  final String cveId;
  final String vendor;
  final String product;
  final String name;
  final String dateAdded;
  final String? dueDate;
  final String ransomware;
  final bool hasRecord;
  final String? severity;
  final double? cvss;
}

class VulnerabilityDetail {
  VulnerabilityDetail.fromJson(Map<String, dynamic> j)
    : cveId = _s(j['cve_id']) ?? '',
      recordAvailable = _b(j['record_available']),
      state = _s(j['state']) ?? '',
      title = _s(j['title']),
      description = _s(j['description']),
      assigner = _s(j['assigner']),
      published = _s(j['published_at']),
      severity = _s(j['severity']),
      cvss = _d(j['cvss_base_score']),
      cvssVersion = _s(j['cvss_version']),
      cvssProvider = _s(j['cvss_provider']),
      severityRule = _s(j['severity_rule']) ?? '',
      scores = _maps(j['cvss']),
      cwes = _maps(j['cwes']),
      affected = _maps(j['affected']),
      references = _maps(j['references']),
      kev = j['kev'] is Map ? _map(j['kev']) : null,
      advisories = _maps(j['advisories']),
      provenance = _maps(j['provenance']);

  final String cveId;
  final bool recordAvailable;
  final String state;
  final String? title;
  final String? description;
  final String? assigner;
  final String? published;
  final String? severity;
  final double? cvss;
  final String? cvssVersion;
  final String? cvssProvider;
  final String severityRule;
  final List<Map<String, dynamic>> scores;
  final List<Map<String, dynamic>> cwes;
  final List<Map<String, dynamic>> affected;
  final List<Map<String, dynamic>> references;
  final Map<String, dynamic>? kev;
  final List<Map<String, dynamic>> advisories;
  final List<Map<String, dynamic>> provenance;
}

class Correlation {
  Correlation.fromJson(Map<String, dynamic> j)
    : weaknesses = _maps(j['weaknesses']),
      patterns = _maps(j['attack_patterns']),
      techniques = _maps(j['techniques']),
      related = _maps(j['related_vulnerabilities']),
      notes = _strings(j['notes']),
      rules = _maps(j['rules']);

  final List<Map<String, dynamic>> weaknesses;
  final List<Map<String, dynamic>> patterns;
  final List<Map<String, dynamic>> techniques;
  final List<Map<String, dynamic>> related;
  final List<String> notes;
  final List<Map<String, dynamic>> rules;
}

class SearchHit {
  SearchHit.fromJson(Map<String, dynamic> j)
    : entityType = _s(j['entity_type']) ?? '',
      entityId = _s(j['entity_id']) ?? '',
      cveId = _s(j['cve_id']),
      title = _s(j['title']) ?? '',
      snippet = _s(j['snippet']) ?? '',
      sourceName = _s(j['source_name']) ?? '',
      sourceUrl = _s(j['source_url']),
      score = _d(j['score']) ?? 0,
      severity = _s(_map(j['metadata'])['severity']),
      inKev = _b(_map(j['metadata'])['in_kev']);

  final String entityType;
  final String entityId;
  final String? cveId;
  final String title;
  final String snippet;
  final String sourceName;
  final String? sourceUrl;
  final double score;
  final String? severity;
  final bool inKev;
}

class SearchResult {
  SearchResult.fromJson(Map<String, dynamic> j)
    : mode = _s(j['mode']) ?? '',
      embeddingModel = _s(j['embedding_model']),
      semantic = _b(j['semantic_model']),
      warnings = _strings(j['warnings']),
      hits = _maps(j['results']).map(SearchHit.fromJson).toList();

  final String mode;
  final String? embeddingModel;
  final bool semantic;
  final List<String> warnings;
  final List<SearchHit> hits;
}

class Citation {
  Citation.fromJson(Map<String, dynamic> j)
    : id = _s(j['id']) ?? '',
      entityType = _s(j['entity_type']) ?? '',
      entityId = _s(j['entity_id']) ?? '',
      cveId = _s(j['cve_id']),
      title = _s(j['title']) ?? '',
      sourceName = _s(j['source_name']) ?? '',
      sourceUrl = _s(j['source_url']),
      snippet = _s(j['snippet']) ?? '';

  final String id;
  final String entityType;
  final String entityId;
  final String? cveId;
  final String title;
  final String sourceName;
  final String? sourceUrl;
  final String snippet;
}

class ChatAnswer {
  ChatAnswer.fromJson(Map<String, dynamic> j)
    : answer = _s(j['answer']) ?? '',
      mode = _s(j['mode']) ?? '',
      grounded = _b(j['grounded']),
      citations = _maps(j['citations']).map(Citation.fromJson).toList(),
      facts = _maps(j['facts']),
      warnings = _strings(j['warnings']),
      model = j['model'] is Map ? _map(j['model']) : null,
      disclaimer = _s(j['disclaimer']) ?? '',
      latencyMs = _d(j['latency_ms']) ?? 0;

  final String answer;
  final String mode;
  final bool grounded;
  final List<Citation> citations;
  final List<Map<String, dynamic>> facts;
  final List<String> warnings;
  final Map<String, dynamic>? model;
  final String disclaimer;
  final double latencyMs;
}

class DependencyFinding {
  DependencyFinding.fromJson(Map<String, dynamic> j)
    : package = _s(j['package']) ?? '',
      version = _s(j['version']),
      specifier = _s(j['specifier']),
      confidence = _s(j['confidence']) ?? 'uncertain',
      reason = _s(j['reason']) ?? '',
      advisoryId = _s(j['advisory_id']),
      cveIds = _strings(j['cve_ids']),
      severity = _s(j['severity']),
      summary = _s(j['summary']),
      fixedVersions = _strings(j['fixed_versions']),
      inKev = _b(j['in_kev']),
      source = _s(j['source']) ?? '',
      references = _strings(j['references']);

  final String package;
  final String? version;
  final String? specifier;
  final String confidence;
  final String reason;
  final String? advisoryId;
  final List<String> cveIds;
  final String? severity;
  final String? summary;
  final List<String> fixedVersions;
  final bool inKev;
  final String source;
  final List<String> references;
}

class DependencyReport {
  DependencyReport.fromJson(Map<String, dynamic> j)
    : filename = _s(j['filename']) ?? '',
      format = _s(j['format']) ?? '',
      ecosystem = _s(j['ecosystem']) ?? '',
      dependencyCount = _i(j['dependency_count']),
      checkedCount = _i(j['checked_count']),
      unpinnedCount = _i(j['unpinned_count']),
      vulnerablePackages = _i(j['vulnerable_packages']),
      findings = _maps(j['findings']).map(DependencyFinding.fromJson).toList(),
      notChecked = _maps(j['not_checked']),
      warnings = _strings(j['warnings']);

  final String filename;
  final String format;
  final String ecosystem;
  final int dependencyCount;
  final int checkedCount;
  final int unpinnedCount;
  final int vulnerablePackages;
  final List<DependencyFinding> findings;
  final List<Map<String, dynamic>> notChecked;
  final List<String> warnings;
}

class Stats {
  Stats.fromJson(Map<String, dynamic> j)
    : vulnerabilities = _i(j['vulnerabilities']),
      kevEntries = _i(j['kev_entries']),
      kevWithRecord = _i(j['kev_with_cve_record']),
      techniques = _i(j['attack_techniques']),
      capecPatterns = _i(j['capec_patterns']),
      advisories = _i(j['advisories']),
      chunks = _i(j['document_chunks']),
      embeddedChunks = _i(j['embedded_chunks']),
      bySeverity = _maps(j['by_severity']),
      topCwes = _maps(j['top_cwes']),
      recentKev = _maps(j['recent_kev']).map(KevItem.fromJson).toList();

  final int vulnerabilities;
  final int kevEntries;
  final int kevWithRecord;
  final int techniques;
  final int capecPatterns;
  final int advisories;
  final int chunks;
  final int embeddedChunks;
  final List<Map<String, dynamic>> bySeverity;
  final List<Map<String, dynamic>> topCwes;
  final List<KevItem> recentKev;
}

class SourceStatus {
  SourceStatus.fromJson(Map<String, dynamic> j)
    : code = _s(j['code']) ?? '',
      name = _s(j['name']) ?? '',
      lastSuccess = _s(j['last_success_at']),
      records = _i(j['tracked_records']),
      latestStatus = _s(_map(j['latest_job'])['status']);

  final String code;
  final String name;
  final String? lastSuccess;
  final int records;
  final String? latestStatus;
}

class Readiness {
  Readiness.fromJson(Map<String, dynamic> j)
    : status = _s(j['status']) ?? 'unknown',
      checks = _map(j['checks']).map((k, v) => MapEntry(k, _map(v)));

  final String status;
  final Map<String, Map<String, dynamic>> checks;
}
