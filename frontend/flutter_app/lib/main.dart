import 'package:flutter/material.dart';

import 'src/api/api_client.dart';
import 'src/app.dart';

void main() {
  runApp(CtiApp(client: ApiClient()));
}
