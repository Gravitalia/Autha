FROM node:21-alpine3.18 as builder

USER node
WORKDIR /autha

COPY . .

RUN yarn install --frozen-lockfile && \
    yarn build

FROM node:21-alpine3.18 as runtime
ENV NODE_ENV production

USER node

WORKDIR /

COPY --from=builder /autha/.output .output
COPY --from=builder /autha/package.json package.json
COPY --from=builder /autha/node_modules node_modules

EXPOSE  3000
CMD     ["yarn", "preview"]
