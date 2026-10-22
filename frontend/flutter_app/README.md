# Flutter client

The user interface for the Cyber Threat Intelligence platform. It talks only to the
backend REST API (`/api/v1`) and holds no secrets.

Screens: dashboard (system status, dataset counts, latest KEV additions, sources),
vulnerability search (filtered full-text or semantic), CISA KEV list, CVE detail with
threat correlation, evidence-grounded Q&A, and dependency analysis (file upload or paste).

## Run

Requirements: Flutter 3.47 (Dart 3.13) or newer, and the backend running with
`CORS_ORIGINS` including the web origin.

```bash
flutter pub get
# Web (Chrome); the backend must allow this origin in CORS_ORIGINS
flutter run -d chrome --web-port 8090 --dart-define=API_BASE_URL=http://localhost:8000
# Android emulator: the default base URL is http://10.0.2.2:8000 (the host machine)
flutter run -d emulator-5554
# Physical device: use the host's LAN address
flutter run --dart-define=API_BASE_URL=http://192.168.1.20:8000
```

Production web build that works offline (no CanvasKit download from Google's CDN):

```bash
flutter build web --release --no-web-resources-cdn --dart-define=API_BASE_URL=https://api.example.org
# serve build/web with any static file server
```

## Test

```bash
flutter analyze
flutter test
```

Tests use `package:http/testing.dart` mocks; no backend is needed.
