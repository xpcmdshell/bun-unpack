import picture from './assets/picture.svg';
import binary from './assets/binary.png';
import empty from './assets/empty.svg';

async function main(): Promise<void> {
  const contents = await Promise.all([
    Bun.file(picture).text(),
    Bun.file(binary).arrayBuffer(),
    Bun.file(empty).text(),
  ]);
  console.log(contents[0], new Uint8Array(contents[1]).length, contents[2]);
}

main();
