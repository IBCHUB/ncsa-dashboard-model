import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';

const requiredEnv = [
  'ELASTICSEARCH_URL',
  'WAREHOUSE_INDEX',
  'DATALAKE_INDEX',
  'ELASTICSEARCH_API_KEY',
  'ELASTICSEARCH_DATALAKE_API_KEY',
];

const missingEnv = requiredEnv.filter((name) => !process.env[name]);
const port = Number(process.env.TEST_PORT || '3110');
const baseUrl = `http://127.0.0.1:${port}`;
const dashboardDir = process.cwd();
const standaloneServer = path.join(dashboardDir, '.next', 'standalone', 'server.js');

async function waitForServer() {
  const deadline = Date.now() + 30_000;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/threat-level`);
      if (response.ok) {
        return;
      }
    } catch {
      // Keep polling until the standalone server is ready.
    }

    await delay(500);
  }

  throw new Error('Standalone server did not become ready within 30 seconds.');
}

if (missingEnv.length > 0) {
  test(
    'analytics API smoke tests require ELK environment variables',
    { skip: `Missing env: ${missingEnv.join(', ')}` },
    () => {}
  );
} else {
  let serverProcess;

  test.before(async () => {
    serverProcess = spawn(process.execPath, [standaloneServer], {
      cwd: dashboardDir,
      env: {
        ...process.env,
        PORT: String(port),
        HOSTNAME: '127.0.0.1'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    });

    serverProcess.stdout.on('data', () => {});
    serverProcess.stderr.on('data', () => {});

    await waitForServer();
  });

  test.after(() => {
    if (serverProcess && !serverProcess.killed) {
      serverProcess.kill('SIGTERM');
    }
  });

  test('GET /api/threat-level returns the required contract', async () => {
    const response = await fetch(`${baseUrl}/api/threat-level`);
    assert.equal(response.status, 200);

    const payload = await response.json();
    assert.equal(typeof payload.date, 'string');
    assert.equal(typeof payload.score, 'number');
    assert.ok(['low', 'guarded', 'elevated', 'critical'].includes(payload.level));
    assert.deepEqual(
      Object.keys(payload.factors).sort(),
      ['actor', 'sector', 'severity', 'volume']
    );
    assert.ok(Array.isArray(payload.top_sectors));
    assert.ok(Array.isArray(payload.named_actors));
  });

  test('GET /api/trend-analytics returns forecast and comparison charts', async () => {
    const response = await fetch(`${baseUrl}/api/trend-analytics`);
    assert.equal(response.status, 200);

    const payload = await response.json();
    assert.equal(payload.meta.window_hours, 24);
    assert.equal(payload.meta.forecast_hours, 24);
    assert.deepEqual(
      Object.keys(payload.comparison_charts).sort(),
      ['countries', 'sectors', 'sources', 'threat_types']
    );
    assert.equal(payload.attack_volume_trend.historical.length, 24);
    assert.equal(payload.attack_volume_trend.forecast.length, 24);
    assert.ok(Array.isArray(payload.threat_volume_trend));
  });

  test('GET /api/attack-graph returns graph data and capability flags', async () => {
    const response = await fetch(`${baseUrl}/api/attack-graph?mode=with_entities&limit=20`);
    assert.equal(response.status, 200);

    const payload = await response.json();
    assert.ok(payload.data);
    assert.ok(Array.isArray(payload.data.nodes));
    assert.ok(Array.isArray(payload.data.links));
    assert.equal(typeof payload.capabilities.campaigns, 'boolean');
    assert.equal(typeof payload.stats.links, 'number');
  });
}
