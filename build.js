import esbuild from 'esbuild';

esbuild.build({
  entryPoints: ['./src/index.mjs'],
  bundle: true,           // bundle all dependencies into single file
  platform: 'node',       // Node.js target
  target: 'node22',       // Node 22 Lambda@Edge
  outfile: 'dist/index.mjs',
  format: 'esm',          // ES Modules
  minify: true,           // minify to reduce size
  sourcemap: false,
  external: [],           // include all dependencies
}).then(() => {
  console.log('✅ Build completed. File: dist/index.mjs');
}).catch((err) => {
  console.error(err);
  process.exit(1);
});