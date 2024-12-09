/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    "./layouts/**/*.html",
    "./content/**/*.{html,md}",
    "./assets/**/*.js",
  ],
  theme: {
    extend: {
      keyframes: {
        'open-menu': {
          '0%': { transform: 'scaleY(0)' },
          '100%': { transform: 'scaleY(1)' },
        },
      },
      animation: {
        'open-menu': 'open-menu 0.3s ease-in-out forwards',
      },
    },
  },
  future: {
    // disable hover on touch devices
    hoverOnlyWhenSupported: true,
  },
  safelist: [
    {
      pattern: /grid-cols-.+/, 
    },
  ]
}

