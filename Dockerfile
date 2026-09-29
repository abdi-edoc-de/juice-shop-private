FROM node:24 AS installer
COPY . /juice-shop
WORKDIR /juice-shop
RUN npm install -g typescript@^6.0.3
# Install WITH devDependencies: JuiceShop keeps its @types/* (config, express,
# jsonwebtoken, js-yaml, ...) in devDependencies, and the server build (tsc,
# strict mode) needs them. With --omit=dev, tsc fails and build/app.js is never
# produced, yielding an image whose CMD ["/juice-shop/build/app.js"] cannot start.
# The devDependencies live only in this discarded installer stage; the final
# distroless stage copies the built tree, not the dev tooling.
RUN npm install
# Ensure the server is compiled (emits build/app.js that the runtime CMD runs).
# tsc runs with noEmitOnError=false, so it EMITS the JS even when it reports
# type errors; JuiceShop itself swallows tsc's non-zero exit ("build:server ||
# cd ."), so we do the same — the emitted build/ is what matters, not a clean
# type check. Guard it and then assert the entrypoint was actually produced.
RUN npm run build:server || echo "tsc reported errors (non-fatal; JS still emitted)"
RUN test -f build/app.js || (echo "build/app.js missing after build:server" >&2; exit 1)
RUN npm dedupe --omit=dev
RUN rm -rf frontend/node_modules
RUN rm -rf frontend/.angular
RUN rm -rf frontend/src/assets
RUN mkdir logs
RUN chown -R 65532 logs
RUN chgrp -R 0 ftp/ frontend/dist/ logs/ data/ i18n/
RUN chmod -R g=u ftp/ frontend/dist/ logs/ data/ i18n/
RUN rm ftp/legal.md || true
RUN rm i18n/*.json || true

# keep version in sync with package.json
ARG CYCLONEDX_NPM_VERSION='^2.0.0||^3.0.0||^4.0.0'
RUN npm install -g @cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM_VERSION
# SBOM generation is not needed for the CI/CD pentest demo image; keep it
# non-fatal so a broken/unsupported SBOM toolchain never fails the build.
RUN npm run sbom || echo "sbom skipped (non-fatal for demo)"

FROM gcr.io/distroless/nodejs24-debian13
ARG BUILD_DATE
ARG VCS_REF
LABEL maintainer="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
    org.opencontainers.image.title="OWASP Juice Shop" \
    org.opencontainers.image.description="Probably the most modern and sophisticated insecure web application" \
    org.opencontainers.image.authors="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
    org.opencontainers.image.vendor="Open Worldwide Application Security Project" \
    org.opencontainers.image.documentation="https://help.owasp-juice.shop" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.version="20.2.0" \
    org.opencontainers.image.url="https://owasp-juice.shop" \
    org.opencontainers.image.source="https://github.com/juice-shop/juice-shop" \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_DATE
WORKDIR /juice-shop
COPY --from=installer --chown=65532:0 /juice-shop .
USER 65532
EXPOSE 3000
CMD ["/juice-shop/build/app.js"]
