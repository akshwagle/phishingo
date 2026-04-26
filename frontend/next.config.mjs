/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals = [...(config.externals || []), 'canvas', 'bufferutil', 'utf-8-validate']
    }
    return config
  },
}

export default nextConfig
