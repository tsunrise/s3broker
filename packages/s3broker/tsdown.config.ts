import { defineConfig } from 'tsdown';

export default defineConfig({
	entry: ['src/index.ts', 'src/sigv4.ts'],
	format: ['esm', 'cjs'],
	dts: true,
	clean: true,
	minify: true,
	external: ['aws4fetch', 'zod'],
	outDir: 'dist',
});
