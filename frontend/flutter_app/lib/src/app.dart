import 'package:flutter/material.dart';

import 'api/api_client.dart';
import 'screens/chat_screen.dart';
import 'screens/dashboard_screen.dart';
import 'screens/dependencies_screen.dart';
import 'screens/kev_screen.dart';
import 'screens/search_screen.dart';
import 'widgets/common.dart';

class CtiApp extends StatelessWidget {
  const CtiApp({super.key, required this.client});

  final ApiClient client;

  @override
  Widget build(BuildContext context) {
    const seed = Color(0xFF1F4E79);
    return ApiScope(
      client: client,
      child: MaterialApp(
        title: 'Cyber Threat Intelligence',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(colorSchemeSeed: seed, useMaterial3: true),
        darkTheme: ThemeData(
          colorSchemeSeed: seed,
          brightness: Brightness.dark,
          useMaterial3: true,
        ),
        home: const HomeShell(),
      ),
    );
  }
}

class _Destination {
  const _Destination(this.label, this.icon, this.builder);

  final String label;
  final IconData icon;
  final Widget Function() builder;
}

final _destinations = <_Destination>[
  _Destination('Dashboard', Icons.dashboard_outlined, () => const DashboardScreen()),
  _Destination('Search', Icons.search, () => const SearchScreen()),
  _Destination('KEV', Icons.warning_amber_rounded, () => const KevScreen()),
  _Destination('Ask', Icons.forum_outlined, () => const ChatScreen()),
  _Destination('Packages', Icons.inventory_2_outlined, () => const DependenciesScreen()),
];

/// Navigation rail on wide screens, bottom navigation bar on phones.
class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _index = 0;
  // Keep each tab's state while switching tabs.
  final _pages = List<Widget?>.filled(_destinations.length, null);

  @override
  Widget build(BuildContext context) {
    _pages[_index] ??= _destinations[_index].builder();
    final body = IndexedStack(
      index: _index,
      children: [for (final p in _pages) p ?? const SizedBox.shrink()],
    );
    final wide = MediaQuery.sizeOf(context).width >= 840;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Cyber Threat Intelligence'),
        actions: [
          if (wide)
            Padding(
              padding: const EdgeInsets.only(right: 12),
              child: Center(
                child: Text(
                  ApiScope.of(context).baseUrl,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ),
        ],
      ),
      body: wide
          ? Row(
              children: [
                NavigationRail(
                  selectedIndex: _index,
                  labelType: NavigationRailLabelType.all,
                  onDestinationSelected: (i) => setState(() => _index = i),
                  destinations: [
                    for (final d in _destinations)
                      NavigationRailDestination(icon: Icon(d.icon), label: Text(d.label)),
                  ],
                ),
                const VerticalDivider(width: 1),
                Expanded(child: body),
              ],
            )
          : body,
      bottomNavigationBar: wide
          ? null
          : NavigationBar(
              selectedIndex: _index,
              onDestinationSelected: (i) => setState(() => _index = i),
              destinations: [
                for (final d in _destinations)
                  NavigationDestination(icon: Icon(d.icon), label: d.label),
              ],
            ),
    );
  }
}
