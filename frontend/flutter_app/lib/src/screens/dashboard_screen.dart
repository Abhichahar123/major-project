import 'package:flutter/material.dart';

import '../api/models.dart';
import '../widgets/common.dart';
import 'vulnerability_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardData {
  _DashboardData(this.stats, this.sources, this.readiness);

  final Stats stats;
  final List<SourceStatus> sources;
  final Readiness? readiness;
}

class _DashboardScreenState extends State<DashboardScreen> {
  Future<_DashboardData>? _future;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _future ??= _load();
  }

  Future<_DashboardData> _load() async {
    final api = ApiScope.of(context);
    final results = await Future.wait([api.stats(), api.sources()]);
    Readiness? readiness;
    try {
      readiness = await api.readiness();
    } catch (_) {
      readiness = null; // the dashboard still works without readiness details
    }
    return _DashboardData(results[0] as Stats, results[1] as List<SourceStatus>, readiness);
  }

  void _reload() => setState(() => _future = _load());

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<_DashboardData>(
      future: _future,
      builder: (context, snapshot) {
        if (snapshot.hasError) return ErrorView(error: snapshot.error!, onRetry: _reload);
        if (!snapshot.hasData) return const LoadingView(message: 'Loading dashboard…');
        final data = snapshot.data!;
        return RefreshIndicator(
          onRefresh: () async => _reload(),
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              if (data.readiness != null) _ReadinessCard(data.readiness!),
              _CountsGrid(data.stats),
              _SeverityCard(data.stats),
              _RecentKevCard(data.stats.recentKev),
              _SourcesCard(data.sources),
            ],
          ),
        );
      },
    );
  }
}

class _ReadinessCard extends StatelessWidget {
  const _ReadinessCard(this.readiness);

  final Readiness readiness;

  @override
  Widget build(BuildContext context) {
    IconData icon(String? status) => switch (status) {
      'ok' => Icons.check_circle,
      'degraded' => Icons.info,
      _ => Icons.error,
    };
    return SectionCard(
      title: 'System status',
      trailing: Tag(readiness.status.toUpperCase(), icon: icon(readiness.status)),
      child: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [
          for (final entry in readiness.checks.entries)
            Tooltip(
              message: '${entry.value['detail'] ?? ''}',
              child: Tag(
                '${entry.key}: ${entry.value['status']}',
                icon: icon(entry.value['status'] as String?),
              ),
            ),
        ],
      ),
    );
  }
}

class _CountsGrid extends StatelessWidget {
  const _CountsGrid(this.stats);

  final Stats stats;

  @override
  Widget build(BuildContext context) {
    final items = [
      ('CVE records', stats.vulnerabilities, Icons.bug_report_outlined),
      ('KEV entries', stats.kevEntries, Icons.warning_amber_rounded),
      ('ATT&CK techniques', stats.techniques, Icons.account_tree_outlined),
      ('CAPEC patterns', stats.capecPatterns, Icons.pattern),
      ('Package advisories', stats.advisories, Icons.inventory_2_outlined),
      ('Indexed chunks', stats.embeddedChunks, Icons.manage_search),
    ];
    return LayoutBuilder(
      builder: (context, constraints) {
        final columns = constraints.maxWidth > 900
            ? 6
            : constraints.maxWidth > 500
            ? 3
            : 2;
        return GridView(
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: columns,
            mainAxisExtent: 112,
          ),
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          children: [
            for (final (label, value, icon) in items)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(icon, size: 20),
                      const SizedBox(height: 4),
                      Text('$value', style: Theme.of(context).textTheme.headlineSmall),
                      Text(
                        label,
                        style: Theme.of(context).textTheme.bodySmall,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ),
          ],
        );
      },
    );
  }
}

class _SeverityCard extends StatelessWidget {
  const _SeverityCard(this.stats);

  final Stats stats;

  @override
  Widget build(BuildContext context) {
    final total = stats.bySeverity.fold<int>(
      0,
      (sum, s) => sum + ((s['count'] as num?)?.toInt() ?? 0),
    );
    return SectionCard(
      title: 'CVE records by severity',
      child: total == 0
          ? const Text('No CVE records ingested yet.')
          : Column(
              children: [
                for (final s in stats.bySeverity)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Row(
                      children: [
                        SizedBox(width: 110, child: Text('${s['key']}')),
                        Expanded(
                          child: LinearProgressIndicator(
                            value: ((s['count'] as num?) ?? 0) / total,
                            color: severityColor(
                              s['key'] as String?,
                              Theme.of(context).colorScheme,
                            ),
                            minHeight: 10,
                          ),
                        ),
                        SizedBox(
                          width: 56,
                          child: Text('  ${s['count']}', textAlign: TextAlign.end),
                        ),
                      ],
                    ),
                  ),
                const SizedBox(height: 8),
                Text(
                  'Top weaknesses: ${stats.topCwes.take(5).map((c) => c['key']).join(', ')}',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ],
            ),
    );
  }
}

class _RecentKevCard extends StatelessWidget {
  const _RecentKevCard(this.items);

  final List<KevItem> items;

  @override
  Widget build(BuildContext context) => SectionCard(
    title: 'Latest CISA KEV additions',
    child: items.isEmpty
        ? const Text('The KEV catalog has not been ingested yet.')
        : Column(
            children: [
              for (final k in items)
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text('${k.cveId} · ${k.vendor} ${k.product}'),
                  subtitle: Text('${k.name}\nAdded ${k.dateAdded}'),
                  isThreeLine: true,
                  trailing: KevBadge(ransomware: k.ransomware),
                  onTap: () => openVulnerability(context, k.cveId),
                ),
            ],
          ),
  );
}

class _SourcesCard extends StatelessWidget {
  const _SourcesCard(this.sources);

  final List<SourceStatus> sources;

  @override
  Widget build(BuildContext context) => SectionCard(
    title: 'Data sources',
    child: Column(
      children: [
        for (final s in sources)
          ListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            title: Text(s.name),
            subtitle: Text(
              s.lastSuccess == null
                  ? 'Never synchronised'
                  : 'Last success ${s.lastSuccess!.substring(0, 16).replaceAll('T', ' ')} UTC · '
                        '${s.records} records',
            ),
            trailing: Tag(s.latestStatus ?? 'no jobs'),
          ),
      ],
    ),
  );
}
