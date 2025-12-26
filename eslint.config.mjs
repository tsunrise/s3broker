import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
	eslint.configs.recommended,
	...tseslint.configs.recommended,
	{
		languageOptions: {
			parserOptions: {
				projectService: true,
				tsconfigRootDir: import.meta.dirname,
			},
		},
		rules: {
			// All promises must be used (awaited or fed elsewhere)
			'@typescript-eslint/no-floating-promises': 'error',

			// Unused variables not allowed unless prefixed with _
			'@typescript-eslint/no-unused-vars': [
				'error',
				{
					argsIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					caughtErrorsIgnorePattern: '^_',
				},
			],

			// Allow @ts-ignore (some edge cases need it)
			'@typescript-eslint/ban-ts-comment': 'off',

			// Allow empty interfaces (sometimes useful for extension)
			'@typescript-eslint/no-empty-object-type': 'off',

			// Allow this aliasing (useful in closures)
			'@typescript-eslint/no-this-alias': 'off',
		},
	},
	{
		// Ignore generated files, config files, and node_modules
		ignores: ['**/node_modules/**', '**/dist/**', '**/*.js', '*.mjs', 'vitest.config.mts', 'worker-configuration.d.ts'],
	},
);
