/** @type {import('next').NextConfig} */
// 폐쇄망 번들 반입(서버 액션 파일 업로드) — API 한도(50MB)와 맞춘다.
export default { output: "standalone", poweredByHeader: false, experimental: { serverActions: { bodySizeLimit: "50mb" } } };
