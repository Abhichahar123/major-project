import 'dart:convert';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../api/models.dart';
import '../widgets/common.dart';
import 'vulnerability_screen.dart';

const _formats = {
  'requirements.txt': 'requirements.txt (PyPI)',
  'package-lock.json': 'package-lock.json (npm)',
  'package.json': 'package.json (npm ranges)',
};
const _maxBytes = 512 * 1024;

/// Upload or paste a manifest; results separate confirmed and uncertain findings.
class DependenciesScreen extends StatefulWidget {
  const DependenciesScreen({super.key, this.pickFile});

  /// Injectable for tests; defaults to the platform file picker.
  final Future<(String, Uint8List)?> Function()? pickFile;

  @override
  State<DependenciesScreen> createState() => _DependenciesScreenState();
}

class _DependenciesScreenState extends State<DependenciesScreen> {
  final _text = TextEditingController();
  String _format = 'requirements.txt';
  bool _busy = false;
  Object? _error;
  DependencyReport? _report;

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  Future<(String, Uint8List)?> _defaultPick() async {
    final file = await FilePicker.pickFile(
      type: FileType.custom,
      allowedExtensions: const ['txt', 'json'],
    );
    if (file == null) return null;
    return (file.name, await file.readAsBytes());
  }

  Future<void> _upload(String filename, Uint8List bytes) async {
    if (bytes.length > _maxBytes) {
      setState(() => _error = 'The file is larger than 512 KB.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
      _report = null;
    });
    try {
      final report = await ApiScope.of(context).analyzeDependencies(filename, bytes);
      setState(() => _report = report);
    } catch (e) {
      setState(() => _error = e);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _pick() async {
    final picked = await (widget.pickFile ?? _defaultPick)();
    if (picked != null) await _upload(picked.$1, picked.$2);
  }

  Future<void> _analyzePasted() async {
    final text = _text.text;
    if (text.trim().isEmpty) {
      setState(() => _error = 'Paste the contents of a manifest first.');
      return;
    }
    await _upload(_format, Uint8List.fromList(utf8.encode(text)));
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Text('Dependency vulnerability analysis', style: theme.textTheme.titleLarge),
        const SizedBox(height: 4),
        const Text(
          'Upload requirements*.txt, package-lock.json or package.json. Files are '
          'parsed as text only: nothing is installed or executed, and uploads are not stored.',
        ),
        const SizedBox(height: 12),
        Align(
          alignment: Alignment.centerLeft,
          child: FilledButton.icon(
            onPressed: _busy ? null : _pick,
            icon: const Icon(Icons.upload_file),
            label: const Text('Choose file'),
          ),
        ),
        const SizedBox(height: 12),
        DropdownButtonFormField<String>(
          initialValue: _format,
          isExpanded: true,
          decoration: const InputDecoration(
            labelText: 'Or paste the contents below as',
            border: OutlineInputBorder(),
          ),
          onChanged: _busy ? null : (v) => setState(() => _format = v ?? _format),
          items: [
            for (final e in _formats.entries)
              DropdownMenuItem(
                value: e.key,
                child: Text(e.value, overflow: TextOverflow.ellipsis),
              ),
          ],
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _text,
          minLines: 4,
          maxLines: 10,
          decoration: const InputDecoration(
            hintText: 'flask==2.2.4\nrequests==2.30.0',
            border: OutlineInputBorder(),
          ),
          style: const TextStyle(fontFamily: 'monospace'),
        ),
        const SizedBox(height: 8),
        Align(
          alignment: Alignment.centerRight,
          child: OutlinedButton.icon(
            onPressed: _busy ? null : _analyzePasted,
            icon: const Icon(Icons.play_arrow),
            label: const Text('Analyze pasted text'),
          ),
        ),
        const SizedBox(height: 12),
        if (_busy) const LoadingView(message: 'Analysing dependencies…'),
        if (_error != null)
          _error is String
              ? MessageView(icon: Icons.info_outline, title: _error as String)
              : ErrorView(error: _error!),
        if (_report != null) _ReportView(_report!),
      ],
    );
  }
}

class _ReportView extends StatelessWidget {
  const _ReportView(this.report);

  final DependencyReport report;

  @override
  Widget build(BuildContext context) {
    final confirmed = report.findings.where((f) => f.confidence == 'confirmed').toList();
    final uncertain = report.findings.where((f) => f.confidence != 'confirmed').toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        SectionCard(
          title: 'Summary: ${report.filename}',
          child: Wrap(
            spacing: 8,
            runSpacing: 4,
            children: [
              Tag('${report.format} · ${report.ecosystem}'),
              Tag('${report.dependencyCount} dependencies'),
              Tag('${report.checkedCount} pinned'),
              Tag('${report.unpinnedCount} unpinned'),
              Tag('${report.vulnerablePackages} vulnerable package(s)', icon: Icons.shield),
            ],
          ),
        ),
        for (final w in report.warnings)
          ListTile(leading: const Icon(Icons.info_outline), title: Text(w), dense: true),
        if (report.findings.isEmpty)
          const MessageView(
            icon: Icons.verified_outlined,
            title: 'No known vulnerabilities found',
            detail: 'Only advisories in the local dataset were checked.',
          ),
        if (confirmed.isNotEmpty)
          SectionCard(
            title: 'Confirmed (${confirmed.length})',
            trailing: const Tag('exact package and version'),
            child: Column(children: [for (final f in confirmed) _FindingTile(f)]),
          ),
        if (uncertain.isNotEmpty)
          SectionCard(
            title: 'Uncertain (${uncertain.length})',
            trailing: const Tag('verify manually'),
            child: Column(children: [for (final f in uncertain) _FindingTile(f)]),
          ),
        if (report.notChecked.isNotEmpty)
          SectionCard(
            title: 'Not checked (${report.notChecked.length})',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [for (final n in report.notChecked) Text('${n['entry']} — ${n['reason']}')],
            ),
          ),
      ],
    );
  }
}

class _FindingTile extends StatelessWidget {
  const _FindingTile(this.f);

  final DependencyFinding f;

  @override
  Widget build(BuildContext context) => ExpansionTile(
    tilePadding: EdgeInsets.zero,
    title: Text(
      '${f.package} ${f.version ?? f.specifier ?? ''} — '
      '${f.advisoryId ?? f.cveIds.join(', ')}',
    ),
    subtitle: Text(
      f.fixedVersions.isEmpty
          ? 'No fixed version listed'
          : 'Fixed in ${f.fixedVersions.join(', ')}',
    ),
    trailing: SeverityChip(severity: f.severity),
    children: [
      Align(
        alignment: Alignment.centerLeft,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (f.summary != null) Text(f.summary!),
            const SizedBox(height: 4),
            Text('Why: ${f.reason}', style: Theme.of(context).textTheme.bodySmall),
            Text('Source: ${f.source}', style: Theme.of(context).textTheme.bodySmall),
            if (f.inKev) const Padding(padding: EdgeInsets.only(top: 4), child: KevBadge()),
            for (final cve in f.cveIds)
              TextButton(
                onPressed: () => openVulnerability(context, cve),
                child: Text('Open $cve'),
              ),
            for (final r in f.references.take(2)) LinkText(r, r),
          ],
        ),
      ),
    ],
  );
}
