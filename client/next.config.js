/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export', // Это заменяет команду next export
  images: {
    unoptimized: true, // Обязательно для статического экспорта
  },
};

module.exports = nextConfig;
