import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"Space Mono"', '"Courier New"', 'monospace'],
        sans: ['"Space Mono"', '"Courier New"', 'monospace'],
      },
      colors: {
        border:   '#1a1a1a',
        bg:       '#f5f0e8',
        surface:  '#fffefb',
        primary:  '#4f46e5',
        'clay-red':    '#ffb3b3',
        'clay-green':  '#b3f0c8',
        'clay-yellow': '#ffe9a0',
        'clay-blue':   '#b3c8ff',
        'clay-purple': '#d4b3ff',
        'clay-orange': '#ffd0a0',
      },
      borderRadius: {
        DEFAULT: '12px',
        sm:  '8px',
        md:  '12px',
        lg:  '16px',
        xl:  '20px',
        '2xl': '24px',
        full: '9999px',
      },
      boxShadow: {
        clay:    '4px 4px 0px #1a1a1a',
        'clay-sm': '2px 2px 0px #1a1a1a',
        'clay-lg': '6px 6px 0px #1a1a1a',
      },
    },
  },
  plugins: [],
}
export default config
