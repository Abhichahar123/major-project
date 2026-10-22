import 'package:flutter/material.dart';

import '../api/models.dart';
import '../widgets/common.dart';
import 'vulnerability_screen.dart';

class KevScreen extends StatefulWidget {
  const KevScreen({super.key});

  @override
  State<KevScreen> createState() => _KevScreenState();
}

class _KevScreenState extends State<KevScreen> {
  final _query = TextEditingController();
  String? _ransomware;
  final _items = <KevItem>[];
  ApiPage<KevItem>? _page;
  bool _loading = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  @override
  void dispose() {
    _query.dispose();
    super.dispose();
  }

  Future<void> _load({bool more = false}) async {
    setState(() {
      _loading = true;
      _error = null;
      if (!more) _items.clear();
    });
    try {
      final page = await ApiScope.of(context).kev(
        q: _query.text.trim().isEmpty ? null : _query.text,
        ransomware: _ransomware,
        page: more ? (_page?.page ?? 0) + 1 : 1,
      );
      setState(() {
        _page = page;
        _items.addAll(page.items);
      });
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
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
          child: Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _query,
                  onSubmitted: (_) => _load(),
                  maxLength: 200,
                  decoration: const InputDecoration(
                    labelText: 'Vendor, product or CVE ID',
                    prefixIcon: Icon(Icons.search),
                    border: OutlineInputBorder(),
                    counterText: '',
                  ),
                ),
              ),
              const SizedBox(width: 8),
              DropdownButton<String?>(
                value: _ransomware,
                hint: const Text('Ransomware use'),
                onChanged: (v) {
                  setState(() => _ransomware = v);
                  _load();
                },
                items: const [
                  DropdownMenuItem(value: null, child: Text('Any ransomware use')),
                  DropdownMenuItem(value: 'Known', child: Text('Known ransomware use')),
                  DropdownMenuItem(value: 'Unknown', child: Text('Unknown')),
                ],
              ),
            ],
          ),
        ),
        if (_page != null)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                '${_page!.total} CISA KEV entries',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
          ),
        const Divider(),
        Expanded(child: _body()),
      ],
    );
  }

  Widget _body() {
    if (_error != null && _items.isEmpty) return ErrorView(error: _error!, onRetry: _load);
    if (_loading && _items.isEmpty) return const LoadingView();
    if (_items.isEmpty) {
      return const MessageView(icon: Icons.search_off, title: 'No KEV entries match');
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
                      onPressed: _loading ? null : () => _load(more: true),
                      child: Text(_loading ? 'Loading…' : 'Load more'),
                    )
                  : const SizedBox.shrink(),
            ),
          );
        }
        final k = _items[index];
        return ListTile(
          title: Text('${k.cveId} · ${k.vendor} ${k.product}'),
          subtitle: Text(
            '${k.name}\nAdded ${k.dateAdded}'
            '${k.dueDate != null ? ' · due ${k.dueDate}' : ''}'
            '${k.hasRecord ? '' : ' · CVE record not ingested'}',
          ),
          isThreeLine: true,
          leading: k.ransomware == 'Known'
              ? const Tooltip(
                  message: 'Known ransomware use',
                  child: Icon(Icons.coronavirus_outlined),
                )
              : const Icon(Icons.warning_amber_rounded),
          trailing: k.severity != null ? SeverityChip(severity: k.severity, score: k.cvss) : null,
          onTap: () => openVulnerability(context, k.cveId),
        );
      },
    );
  }
}
