
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  output: "standalone", // Required for Docker
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
