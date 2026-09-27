import { greeting } from './src/lib/greeting';
import legacy from './src/lib/legacy.cjs';
import settings from './src/data/settings.json';

async function main(): Promise<void> {
  const { lazy } = await import('./src/features/lazy');
  console.log(JSON.stringify({ greeting: greeting(), legacy, settings, lazy }));
}

main();
