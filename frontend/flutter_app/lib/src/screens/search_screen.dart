import 'package:flutter/material.dart';

import '../api/models.dart';
import '../widgets/common.dart';
import 'vulnerability_screen.dart';

const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/// Vulnerability search: filtered full-text search, or semantic/hybrid evidence search.
class SearchScreen extends StatefulWidget {
  const SearchScreen({super.key});

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends State<SearchScreen> {
  final _query = TextEditingController();
  final _selected = <String>{};
  bool _kevOnly = false;
  bool _semantic = false;
  String _sort = 'relevance';

  bool _loading = false;
  Object? _error;
  ApiPage<VulnerabilitySummary>? _page;
  final _items = <VulnerabilitySummary>[];
  SearchResult? _semanticResult;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _search());
  }

  @override
  void dispose() {
    _query.dispose();
    super.dispose();
  }

  Future<void> _search({bool more = false}) async {
    final api = ApiScope.of(context);
    final q = _query.text.trim();
    if (_semantic && q.length < 2) {
      setState(() => _error = 'Enter at least two characters for semantic search.');
      return;
    }
    setState(() {
      _loading = true;
      _error = null;
      if (!more) _items.clear();
    });
    try {
      if (_semantic) {
        final result = await api.semanticSearch(q, inKev: _kevOnly ? true : null);
        setState(() => _semanticResult = result);
      } else {
        final page = await api.searchVulnerabilities(
          q: q.isEmpty ? null : q,
          severity: _selected.toList(),
          inKev: _kevOnly ? true : null,
          sort: q.isEmpty && _sort == 'relevance' ? 'published' : _sort,
          page: more ? (_page?.page ?? 0) + 1 : 1,
        );
        setState(() {
          _page = page;
          _items.addAll(page.items);
        });
      }
    } catch (e) {
      setState(() => _error = e);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
          child: Column(
            children: [
              TextField(
                controller: _query,
                textInputAction: TextInputAction.search,
                onSubmitted: (_) => _search(),
                maxLength: 200,
                decoration: InputDecoration(
                  labelText: _semantic
                      ? 'Describe what you are looking for'
                      : 'Search CVE ID, product or keywords',
                  hintText: _semantic
                      ? 'e.g. session cookie leak in web framework'
                      : 'e.g. CVE-2021-44228',
                  prefixIcon: const Icon(Icons.search),
                  suffixIcon: IconButton(
                    tooltip: 'Search',
                    icon: const Icon(Icons.arrow_forward),
                    onPressed: _search,
                  ),
                  border: const OutlineInputBorder(),
                  counterText: '',
                ),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 4,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: [
                  SegmentedButton<bool>(
                    segments: const [
                      ButtonSegment(
                        value: false,
                        label: Text('Filtered'),
                        icon: Icon(Icons.filter_list),
                      ),
                      ButtonSegment(
                        value: true,
                        label: Text('Semantic'),
                        icon: Icon(Icons.auto_awesome),
                      ),
                    ],
                    selected: {_semantic},
                    onSelectionChanged: (s) {
                      setState(() => _semantic = s.first);
                      _search();
                    },
                  ),
                  FilterChip(
                    label: const Text('Known exploited (KEV)'),
                    selected: _kevOnly,
                    onSelected: (v) {
                      setState(() => _kevOnly = v);
                      _search();
                    },
                  ),
                  if (!_semantic)
                    for (final s in severities)
                      FilterChip(
                        label: Text(s),
                        selected: _selected.contains(s),
                        onSelected: (v) {
                          setState(() => v ? _selected.add(s) : _selected.remove(s));
                          _search();
                        },
                      ),
                  if (!_semantic)
                    DropdownButton<String>(
                      value: _sort,
                      onChanged: (v) {
                        setState(() => _sort = v ?? 'relevance');
                        _search();
                      },
                      items: const [
                        DropdownMenuItem(value: 'relevance', child: Text('Relevance')),
                        DropdownMenuItem(value: 'published', child: Text('Newest')),
                        DropdownMenuItem(value: 'cvss', child: Text('Highest CVSS')),
                      ],
                    ),
                ],
              ),
            ],
          ),
        ),
        const Divider(),
        Expanded(child: _semantic ? _semanticResults() : _filteredResults()),
      ],
    );
  }

  Widget _filteredResults() {
    if (_error != null && _items.isEmpty) {
      return _error is String
          ? MessageView(icon: Icons.info_outline, title: _error as String)
          : ErrorView(error: _error!, onRetry: _search);
    }
    if (_loading && _items.isEmpty) return const LoadingView(message: 'Searching…');
    if (_items.isEmpty) {
      return const MessageView(
        icon: Icons.search_off,
        title: 'No vulnerabilities match',
        detail: 'Try fewer filters or other keywords. Only ingested records are searched.',
      );
    }
    return ListView.separated(
      itemCount: _items.length + 1,
      separatorBuilder: (_, _) => const Divider(height: 1),
      itemBuilder: (context, index) {
        if (index == _items.length) {
          return Padding(
            padding: const EdgeInsets.all(12),
            child: Center(
              child: _page?.hasMore ?? false
                  ? OutlinedButton(
                      onPressed: _loading ? null : () => _search(more: true),
                      child: Text(_loading ? 'Loading…' : 'Load more'),
                    )
                  : Text('${_page?.total ?? _items.length} result(s)'),
            ),
          );
        }
        final v = _items[index];
        return ListTile(
          title: Text(
            v.title == null ? v.cveId : '${v.cveId} · ${v.title}',
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          subtitle: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(v.snippet ?? 'No description', maxLines: 2, overflow: TextOverflow.ellipsis),
              if (v.inKev) const Padding(padding: EdgeInsets.only(top: 4), child: KevBadge()),
            ],
          ),
          trailing: SeverityChip(severity: v.severity, score: v.cvss),
          onTap: () => openVulnerability(context, v.cveId),
        );
      },
    );
  }

  Widget _semanticResults() {
    if (_error != null) {
      return _error is String
          ? MessageView(icon: Icons.info_outline, title: _error as String)
          : ErrorView(error: _error!, onRetry: _search);
    }
    if (_loading) return const LoadingView(message: 'Retrieving evidence…');
    final result = _semanticResult;
    if (result == null) {
      return const MessageView(
        icon: Icons.auto_awesome,
        title: 'Semantic search',
        detail: 'Describe a vulnerability or technique in your own words.',
      );
    }
    return ListView(
      children: [
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
          child: Wrap(
            spacing: 8,
            children: [
              Tag('mode: ${result.mode}'),
              Tag(result.embeddingModel ?? 'keyword only'),
              if (!result.semantic) const Tag('lexical embedder', icon: Icons.info_outline),
            ],
          ),
        ),
        for (final w in result.warnings)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 2),
            child: Text(w, style: Theme.of(context).textTheme.bodySmall),
          ),
        if (result.hits.isEmpty)
          const MessageView(icon: Icons.search_off, title: 'No matching evidence'),
        for (final hit in result.hits)
          ListTile(
            leading: Icon(switch (hit.entityType) {
              'attack_technique' => Icons.account_tree_outlined,
              'kev' => Icons.warning_amber_rounded,
              _ => Icons.bug_report_outlined,
            }),
            title: Text(hit.title, maxLines: 1, overflow: TextOverflow.ellipsis),
            subtitle: Text(
              '${hit.sourceName} · ${hit.snippet.split('\n').skip(1).join(' ')}',
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: hit.severity != null ? SeverityChip(severity: hit.severity) : null,
            onTap: hit.cveId != null
                ? () => openVulnerability(context, hit.cveId!)
                : () => openLink(context, hit.sourceUrl),
          ),
      ],
    );
  }
}
