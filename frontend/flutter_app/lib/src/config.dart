import 'package:flutter/foundation.dart';

/// Base URL of the backend API, without a trailing slash.
///
/// Set it at build time, e.g.
/// `flutter run -d chrome --dart-define=API_BASE_URL=http://localhost:8000`.
/// Without it, the Android emulator uses the host loopback alias 10.0.2.2 and every
/// other platform uses localhost. The app never embeds secrets: the admin key is not
/// needed for any screen.
String resolveApiBaseUrl() {
  const configured = String.fromEnvironment('API_BASE_URL');
  if (configured.isNotEmpty) {
    return configured.endsWith('/') ? configured.substring(0, configured.length - 1) : configured;
  }
  if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
    return 'http://10.0.2.2:8000';
  }
  return 'http://localhost:8000';
}

const apiPrefix = '/api/v1';
