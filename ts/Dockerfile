FROM --platform=linux/amd64 stagex/pallet-nodejs@sha256:2e09e7bc24546c76afeac30a50404ce4b2d44aa48c4d4950c40304d8bf7e057f AS build

ENV SOURCE_DATE_EPOCH=1

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY . .

RUN npx tsc

FROM --platform=linux/amd64 stagex/core-filesystem@sha256:cd3a66471ce1f630fa77d5c9bd9829f9f9fab6302a1aaa64d67b74f1f069b750 AS run
COPY --from=stagex/core-musl@sha256:a06cf7b4a7c57313e21ece02d460b7393eb64e0b3ee1de00e1408392ccf283f3 / /
COPY --from=stagex/core-libcxx@sha256:414761e604c54982aaf0a33f7aa942652fa3d2de1e4f0802b15fa2413ad7ce71 / /
COPY --from=stagex/core-libcxxabi@sha256:7b515659b7c073329e2cd09037eb0c8bad0a76acd1947efe22c7071a380f465b / /
COPY --from=stagex/core-libunwind@sha256:ef6990326947f5b5bab08083d6f6f0de222efdafbd4036dff0cc33bbf4cf106b / /
COPY --from=stagex/core-brotli@sha256:1d5b8f09db3e0f4dd64b5b82eb774e94b70512f54910d6886eb101472c6f9421 / /
COPY --from=stagex/core-c-ares@sha256:558f81e3c657813478db5fae26ee0a25da2a79dc6c582bf936ed84d3c8df4e05 / /
COPY --from=stagex/core-openssl@sha256:5fbecea19913b8c9bb2e5976b03833d44f99c98290b17ee5ef9b469470b7bbff / /
COPY --from=stagex/core-icu@sha256:6e8aa8df8a3ac43831476fb6534a8ff9e87a1297f09567f3ac100da51f55de19 / /
COPY --from=stagex/core-libnghttp2@sha256:3d13a680e6e777568ac89e2a834bccb79b5495b536a4fa63e487d58d979aac33 / /
COPY --from=stagex/core-zlib@sha256:c20975bf503284715ea83a6480269e0a06af520c3d7fc63a7e84ce7b0c80313a / /
COPY --from=stagex/core-nodejs@sha256:9a4c002f56a4b0455243bfb4b7573c763d04156cc89d1845f7d089b44be596ba / /
COPY --from=build /app/dist /app/dist
COPY --from=build /app/node_modules /app/node_modules
USER 65532:65532
ENTRYPOINT ["node", "/app/dist/index.js"]
