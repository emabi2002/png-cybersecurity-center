/** @type {import('next').NextConfig} */
const nextConfig = {
  // Produce a fully static export in ./out (for Netlify to serve)
  output: "export",
  // Helps static hosting serve nested routes as /path/index.html
  trailingSlash: true,

  // Keep Same.New dev origin allowance if you still run there
  allowedDevOrigins: ["*.preview.same-app.com"],

  images: {
    // Required for static export if you're using <Image />
    unoptimized: true,
    // Keep your existing domains for local/dev usage
    domains: [
      "source.unsplash.com",
      "images.unsplash.com",
      "ext.same-assets.com",
      "ugc.same-assets.com",
    ],
    remotePatterns: [
      {
        protocol: "https",
        hostname: "source.unsplash.com",
        pathname: "/**",
      },
      {
        protocol: "https",
        hostname: "images.unsplash.com",
        pathname: "/**",
      },
      {
        protocol: "https",
        hostname: "ext.same-assets.com",
        pathname: "/**",
      },
      {
        protocol: "https",
        hostname: "ugc.same-assets.com",
        pathname: "/**",
      },
    ],
  },
};

module.exports = nextConfig;
