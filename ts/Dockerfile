FROM --platform=linux/amd64 stagex/pallet-nodejs@sha256:2e09e7bc24546c76afeac30a50404ce4b2d44aa48c4d4950c40304d8bf7e057f AS build

ENV SOURCE_DATE_EPOCH=1

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY . .

RUN npx tsc

FROM --platform=linux/amd64 stagex/core-filesystem@sha256:cd3a66471ce1f630fa77d5c9bd9829f9f9fab6302a1aaa64d67b74f1f069b750 AS run
COPY --from=stagex/core-nodejs@sha256:9a4c002f56a4b0455243bfb4b7573c763d04156cc89d1845f7d089b44be596ba / /
COPY --from=build /app/dist /app/dist
COPY --from=build /app/node_modules /app/node_modules
USER 65532:65532
ENTRYPOINT ["node", "/app/dist/index.js"]
