/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        // Semantic aliases into the single Indigo Aurora theme (global.css vars)
        primary: 'var(--accent)',
        'primary-light': '#a5b4fc',
        bg: 'var(--bg)',
        'bg-card': 'var(--glass-bg)',
        'bg-nav': 'var(--nav-bg)',
        text: 'var(--text)',
        'text-muted': 'var(--text-muted)',
      },
      animation: {
        'fade-in': 'fadeIn 0.4s ease',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: 0, transform: 'translateY(16px)' },
          '100%': { opacity: 1, transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
};
