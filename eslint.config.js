/**
 * ESLint Configuration for Warp_Open
 *
 * Rules focused on:
 * - Vue 3 best practices
 * - Composable naming conventions
 * - TypeScript safety
 * - No side effects in setup
 */

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'src-tauri/**',
      '*.cjs',
      '*.sh'
    ]
  },
  {
    files: ['src/**/*.{ts,vue}'],
    rules: {
      // Composable naming: must start with "use"
      'no-restricted-syntax': [
        'warn',
        {
          selector: "ExportNamedDeclaration > FunctionDeclaration[id.name=/^(?!use)[a-z]/]",
          message: 'Exported composable functions should start with "use" prefix'
        }
      ],

      // Avoid any types
      '@typescript-eslint/no-explicit-any': 'warn',

      // Prefer const
      'prefer-const': 'error',

      // No console in production (allow in dev)
      'no-console': process.env.NODE_ENV === 'production' ? 'warn' : 'off',

      // No unused variables (allow underscore prefix)
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_'
        }
      ],

      // No floating promises
      '@typescript-eslint/no-floating-promises': 'warn',

      // Consistent return types
      '@typescript-eslint/explicit-function-return-type': 'off',

      // Vue specific
      'vue/multi-word-component-names': 'off',
      'vue/no-v-html': 'warn',
      'vue/require-default-prop': 'warn'
    }
  },
  {
    // Stricter rules for composables
    files: ['src/composables/**/*.ts'],
    rules: {
      // Ensure composables start with "use"
      'no-restricted-exports': [
        'error',
        {
          restrictedNamedExports: [
            {
              name: '*',
              message: 'Composable exports must start with "use" prefix'
            }
          ]
        }
      ]
    }
  },
  {
    // Test files can use any
    files: ['**/*.test.ts', '**/*.spec.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      'no-console': 'off'
    }
  }
]
