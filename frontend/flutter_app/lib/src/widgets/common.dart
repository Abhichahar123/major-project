import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../api/api_client.dart';

/// Severity colours chosen to stay distinguishable in light and dark themes; the label
/// is always shown as text so colour is never the only signal.
Color severityColor(String? severity, ColorScheme scheme) => switch (severity) {
  'CRITICAL' => const Color(0xFFB3261E),
  'HIGH' => const Color(0xFFD9480F),
  'MEDIUM' => const Color(0xFFB08800),
  'LOW' => const Color(0xFF2B8A3E),
  _ => scheme.outline,
};

class SeverityChip extends StatelessWidget {
  const SeverityChip({super.key, required this.severity, this.score});

  final String? severity;
  final double? score;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final color = severityColor(severity, scheme);
    final label = severity == null
        ? 'Unscored'
        : score == null
        ? severity!
        : '$severity ${score!.toStringAsFixed(1)}';
    return Semantics(
      label: 'Severity $label',
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          border: Border.all(color: color),
          borderRadius: BorderRadius.circular(6),
        ),
        child: Text(
          label,
          style: TextStyle(color: color, fontWeight: FontWeight.w600, fontSize: 12),
        ),
      ),
    );
  }
}

class KevBadge extends StatelessWidget {
  const KevBadge({super.key, this.ransomware});

  final String? ransomware;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final known = ransomware == 'Known';
    return Tooltip(
      message: known
          ? 'Listed in CISA KEV; known ransomware use'
          : 'Listed in the CISA Known Exploited Vulnerabilities catalog',
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
        decoration: BoxDecoration(
          color: scheme.errorContainer,
          borderRadius: BorderRadius.circular(6),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.warning_amber_rounded, size: 14, color: scheme.onErrorContainer),
            const SizedBox(width: 4),
            Text(
              known ? 'KEV · ransomware' : 'Known exploited',
              style: TextStyle(
                color: scheme.onErrorContainer,
                fontWeight: FontWeight.w600,
                fontSize: 12,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class Tag extends StatelessWidget {
  const Tag(this.text, {super.key, this.icon});

  final String text;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (icon != null) ...[Icon(icon, size: 14), const SizedBox(width: 4)],
          Text(text, style: const TextStyle(fontSize: 12)),
        ],
      ),
    );
  }
}

class LoadingView extends StatelessWidget {
  const LoadingView({super.key, this.message = 'Loading…'});

  final String message;

  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [const CircularProgressIndicator(), const SizedBox(height: 12), Text(message)],
      ),
    ),
  );
}

class MessageView extends StatelessWidget {
  const MessageView({super.key, required this.icon, required this.title, this.detail, this.action});

  final IconData icon;
  final String title;
  final String? detail;
  final Widget? action;

  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 40, color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 12),
          Text(title, style: Theme.of(context).textTheme.titleMedium, textAlign: TextAlign.center),
          if (detail != null) ...[
            const SizedBox(height: 8),
            Text(detail!, textAlign: TextAlign.center),
          ],
          if (action case final a?) ...[const SizedBox(height: 16), a],
        ],
      ),
    ),
  );
}

class ErrorView extends StatelessWidget {
  const ErrorView({super.key, required this.error, this.onRetry});

  final Object error;
  final VoidCallback? onRetry;

  @override
  Widget build(BuildContext context) {
    final api = error is ApiException ? error as ApiException : null;
    return MessageView(
      icon: api?.isNetwork ?? false ? Icons.cloud_off : Icons.error_outline,
      title: api?.isNetwork ?? false ? 'Backend not reachable' : 'Something went wrong',
      detail: api?.message ?? 'Unexpected error.',
      action: onRetry == null
          ? null
          : OutlinedButton.icon(
              onPressed: onRetry,
              icon: const Icon(Icons.refresh),
              label: const Text('Retry'),
            ),
    );
  }
}

class SectionCard extends StatelessWidget {
  const SectionCard({super.key, required this.title, required this.child, this.trailing});

  final String title;
  final Widget child;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) => Card(
    margin: const EdgeInsets.symmetric(vertical: 6),
    child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(child: Text(title, style: Theme.of(context).textTheme.titleMedium)),
              ?trailing,
            ],
          ),
          const SizedBox(height: 8),
          child,
        ],
      ),
    ),
  );
}

/// Opens an external link. Only http(s) URLs are allowed: source data is untrusted.
Future<void> openLink(BuildContext context, String? url) async {
  final uri = url == null ? null : Uri.tryParse(url);
  if (uri == null || !(uri.isScheme('http') || uri.isScheme('https'))) {
    ScaffoldMessenger.of(context)
        .showSnackBar(const SnackBar(content: Text('This link cannot be opened.')));
    return;
  }
  if (!await launchUrl(uri, mode: LaunchMode.externalApplication) && context.mounted) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Could not open $url')));
  }
}

class LinkText extends StatelessWidget {
  const LinkText(this.label, this.url, {super.key});

  final String label;
  final String? url;

  @override
  Widget build(BuildContext context) => InkWell(
    onTap: () => openLink(context, url),
    child: Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Text(
        label,
        style: TextStyle(
          color: Theme.of(context).colorScheme.primary,
          decoration: TextDecoration.underline,
        ),
      ),
    ),
  );
}

/// Makes an [ApiClient] available to the widget tree.
class ApiScope extends InheritedWidget {
  const ApiScope({super.key, required this.client, required super.child});

  final ApiClient client;

  static ApiClient of(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<ApiScope>()!.client;

  @override
  bool updateShouldNotify(ApiScope oldWidget) => client != oldWidget.client;
}
