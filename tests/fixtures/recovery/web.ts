import page from './web/index.html';

async function main(): Promise<void> {
  if (process.argv.includes('--artifact-manifest')) {
    const artifacts = await Promise.all(Bun.embeddedFiles.map(async (file) => ({
      name: file.name,
      sha256: new Bun.CryptoHasher('sha256').update(await file.arrayBuffer()).digest('hex'),
    })));
    console.log(JSON.stringify(artifacts));
    return;
  }
  console.log('WEB_ENTRY', typeof page);
}

main();
