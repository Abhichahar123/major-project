import 'dart:convert';
import 'dart:typed_data';

import 'package:cti_app/src/api/api_client.dart';
import 'package:cti_app/src/app.dart';
import 'package:cti_app/src/screens/chat_screen.dart';
import 'package:cti_app/src/screens/dependencies_screen.dart';
import 'package:cti_app/src/screens/search_screen.dart';
import 'package:cti_app/src/widgets/common.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

import 'fakes.dart';

Widget host(Widget child, ApiClient api) => ApiScope(
  client: api,
  child: MaterialApp(home: Scaffold(body: child)),
);

ApiClient api(Map<String, Object> routes) =>
    ApiClient(client: fakeBackend(routes), baseUrl: 'http://api.test');

void main() {
  testWidgets('severity chip and KEV badge show text labels', (tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Scaffold(
          body: Column(
            children: [
              SeverityChip(severity: 'CRITICAL', score: 9.8),
              SeverityChip(severity: null),
              KevBadge(ransomware: 'Known'),
            ],
          ),
        ),
      ),
    );
    expect(find.text('CRITICAL 9.8'), findsOneWidget);
    expect(find.text('Unscored'), findsOneWidget);
    expect(find.text('KEV · ransomware'), findsOneWidget);
  });

  testWidgets('dashboard shows counts and recent KEV entries', (tester) async {
    tester.view.physicalSize = const Size(1200, 2400);
    addTearDown(tester.view.resetPhysicalSize);
    await tester.pumpWidget(
      CtiApp(
        client: api({
          '/api/v1/stats': stats,
          '/api/v1/sources': <Object>[],
          '/api/v1/health/ready': {
            'status': 'degraded',
            'checks': {
              'database': {'status': 'ok'},
              'llm': {'status': 'degraded', 'detail': 'Ollama not reachable'},
            },
          },
        }),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('KEV entries'), findsOneWidget);
    expect(find.text('llm: degraded'), findsOneWidget);
    await tester.scrollUntilVisible(
      find.textContaining('CVE-2023-4966'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(find.textContaining('CVE-2023-4966'), findsOneWidget);
  });

  testWidgets('dashboard explains an unreachable backend', (tester) async {
    await tester.pumpWidget(
      CtiApp(
        client: ApiClient(
          client: MockClient((_) async => throw http.ClientException('refused')),
          baseUrl: 'http://api.test',
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Backend not reachable'), findsOneWidget);
    expect(find.text('Retry'), findsOneWidget);
  });

  testWidgets('search lists results with severity and KEV', (tester) async {
    await tester.pumpWidget(
      host(const SearchScreen(), api({'/api/v1/vulnerabilities': vulnerabilityPage})),
    );
    await tester.pumpAndSettle();
    expect(find.text('CVE-2021-44228 · Log4Shell'), findsOneWidget);
    expect(find.text('CRITICAL 10.0'), findsOneWidget);
    expect(find.text('Known exploited'), findsOneWidget);
  });

  testWidgets('search shows an empty state', (tester) async {
    await tester.pumpWidget(
      host(
        const SearchScreen(),
        api({
          '/api/v1/vulnerabilities': {'items': <Object>[], 'page': 1, 'page_size': 20, 'total': 0},
        }),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('No vulnerabilities match'), findsOneWidget);
  });

  testWidgets('chat shows answer mode, grounding, facts and citations', (tester) async {
    tester.view.physicalSize = const Size(1200, 3000);
    addTearDown(tester.view.resetPhysicalSize);
    await tester.pumpWidget(host(const ChatScreen(), api({'/api/v1/chat': chatAnswer})));
    await tester.enterText(find.byType(TextField), 'Is Log4Shell exploited?');
    await tester.tap(find.byTooltip('Ask'));
    await tester.pumpAndSettle();

    expect(find.text('Generated answer'), findsOneWidget);
    expect(find.text('Grounded in citations'), findsOneWidget);
    expect(find.text('Source facts (from the database, not the model)'), findsOneWidget);
    expect(find.text('E1'), findsOneWidget);
    expect(find.textContaining('in CISA KEV since 2021-12-10'), findsOneWidget);
  });

  testWidgets('chat ignores too-short questions', (tester) async {
    await tester.pumpWidget(host(const ChatScreen(), api({'/api/v1/chat': chatAnswer})));
    await tester.enterText(find.byType(TextField), 'a');
    await tester.tap(find.byTooltip('Ask'));
    await tester.pumpAndSettle();
    expect(find.text('Generated answer'), findsNothing);
  });

  testWidgets('dependency report separates confirmed and uncertain findings', (tester) async {
    tester.view.physicalSize = const Size(1200, 3000);
    addTearDown(tester.view.resetPhysicalSize);
    await tester.pumpWidget(
      host(
        DependenciesScreen(
          pickFile: () async =>
              ('requirements.txt', Uint8List.fromList(utf8.encode('flask==2.2.4\n'))),
        ),
        api({'/api/v1/dependencies/analyze': dependencyReport}),
      ),
    );
    await tester.tap(find.text('Choose file'));
    await tester.pumpAndSettle();

    expect(find.text('Confirmed (1)'), findsOneWidget);
    expect(find.text('Uncertain (1)'), findsOneWidget);
    expect(find.text('Not checked (1)'), findsOneWidget);
    expect(find.textContaining('Fixed in 2.2.5, 2.3.2'), findsOneWidget);
  });

  testWidgets('dependency screen validates empty paste', (tester) async {
    await tester.pumpWidget(host(const DependenciesScreen(), api({})));
    await tester.tap(find.text('Analyze pasted text'));
    await tester.pump();
    expect(find.text('Paste the contents of a manifest first.'), findsOneWidget);
  });
}
