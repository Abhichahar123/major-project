import 'package:flutter/material.dart';

import '../api/models.dart';
import '../widgets/common.dart';
import 'vulnerability_screen.dart';

/// Evidence-grounded Q&A. Model text, cited evidence and database facts are shown
/// separately, with the answer mode and grounding status always visible.
class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _Exchange {
  _Exchange(this.question);

  final String question;
  ChatAnswer? answer;
  Object? error;
}

class _ChatScreenState extends State<ChatScreen> {
  final _input = TextEditingController();
  final _history = <_Exchange>[];
  bool _busy = false;

  static const _examples = [
    'Is CVE-2021-44228 exploited in the wild and what should I do?',
    'Which Citrix NetScaler vulnerabilities leak session tokens?',
    'How do attackers dump credentials from LSASS memory?',
  ];

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  Future<void> _ask([String? preset]) async {
    final question = (preset ?? _input.text).trim();
    if (question.length < 3 || _busy) return;
    final exchange = _Exchange(question);
    setState(() {
      _history.insert(0, exchange);
      _busy = true;
      _input.clear();
    });
    try {
      exchange.answer = await ApiScope.of(context).ask(question);
    } catch (e) {
      exchange.error = e;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Expanded(
          child: _history.isEmpty
              ? ListView(
                  padding: const EdgeInsets.all(24),
                  children: [
                    const MessageView(
                      icon: Icons.forum_outlined,
                      title: 'Ask a cybersecurity question',
                      detail:
                          'Answers are built only from ingested CVE, KEV and ATT&CK records '
                          'and cite their evidence. Exploit code is never provided.',
                    ),
                    for (final q in _examples)
                      Padding(
                        padding: const EdgeInsets.symmetric(vertical: 4),
                        child: ActionChip(label: Text(q), onPressed: () => _ask(q)),
                      ),
                  ],
                )
              : ListView.builder(
                  reverse: false,
                  padding: const EdgeInsets.all(16),
                  itemCount: _history.length,
                  itemBuilder: (context, i) => _ExchangeCard(_history[i]),
                ),
        ),
        if (_busy) const LinearProgressIndicator(),
        SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _input,
                    minLines: 1,
                    maxLines: 4,
                    maxLength: 1000,
                    enabled: !_busy,
                    // Enter sends; Shift+Enter is not needed for short questions.
                    textInputAction: TextInputAction.send,
                    onSubmitted: (_) => _ask(),
                    decoration: const InputDecoration(
                      hintText: 'e.g. Which KEV entries affect Ivanti products?',
                      border: OutlineInputBorder(),
                      counterText: '',
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  tooltip: 'Ask',
                  onPressed: _busy ? null : _ask,
                  icon: const Icon(Icons.send),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _ExchangeCard extends StatelessWidget {
  const _ExchangeCard(this.exchange);

  final _Exchange exchange;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final answer = exchange.answer;
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(exchange.question, style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            if (exchange.error != null)
              ErrorView(error: exchange.error!)
            else if (answer == null)
              const LoadingView(message: 'Retrieving evidence and generating an answer…')
            else ...[
              Wrap(
                spacing: 8,
                runSpacing: 4,
                children: [
                  Tag(switch (answer.mode) {
                    'generated' => 'Generated answer',
                    'evidence_only' => 'Evidence only (model unavailable)',
                    'insufficient_evidence' => 'Insufficient evidence',
                    'refused' => 'Refused',
                    _ => answer.mode,
                  }),
                  if (answer.mode == 'generated')
                    Tag(
                      answer.grounded ? 'Grounded in citations' : 'Not fully grounded',
                      icon: answer.grounded ? Icons.verified : Icons.report_problem_outlined,
                    ),
                  if (answer.model != null)
                    Tag('${answer.model!['provider']}/${answer.model!['name']}'),
                ],
              ),
              const SizedBox(height: 8),
              SelectableText(answer.answer),
              for (final w in answer.warnings)
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(Icons.info_outline, size: 16, color: theme.colorScheme.tertiary),
                      const SizedBox(width: 6),
                      Expanded(child: Text(w, style: theme.textTheme.bodySmall)),
                    ],
                  ),
                ),
              if (answer.facts.isNotEmpty) ...[
                const SizedBox(height: 12),
                Text(
                  'Source facts (from the database, not the model)',
                  style: theme.textTheme.labelLarge,
                ),
                for (final f in answer.facts)
                  ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    title: Text('${f['cve_id']}'),
                    subtitle: Text(
                      'CVSS ${f['cvss_base_score'] ?? 'n/a'} '
                      '(${f['cvss_provider'] ?? 'no score'}) · '
                      '${f['in_kev'] == true ? 'in CISA KEV since ${f['kev_date_added']}' : 'not in KEV'}'
                      '${(f['cwes'] as List?)?.isNotEmpty ?? false ? ' · ${(f['cwes'] as List).join(', ')}' : ''}',
                    ),
                    trailing: SeverityChip(severity: f['severity'] as String?),
                    onTap: () => openVulnerability(context, f['cve_id'] as String),
                  ),
              ],
              if (answer.citations.isNotEmpty) ...[
                const SizedBox(height: 12),
                Text('Evidence', style: theme.textTheme.labelLarge),
                for (final c in answer.citations)
                  ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: CircleAvatar(
                      radius: 14,
                      child: Text(c.id, style: const TextStyle(fontSize: 10)),
                    ),
                    title: Text(c.title, maxLines: 1, overflow: TextOverflow.ellipsis),
                    subtitle: Text(
                      '${c.sourceName} · ${c.snippet}',
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                    onTap: c.cveId != null
                        ? () => openVulnerability(context, c.cveId!)
                        : () => openLink(context, c.sourceUrl),
                  ),
              ],
              if (answer.disclaimer.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(answer.disclaimer, style: theme.textTheme.bodySmall),
              ],
            ],
          ],
        ),
      ),
    );
  }
}
