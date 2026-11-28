# CI-only packaging of the already-qualified normal agent and the separate
# in-cluster Go qualification controller. Neither target adds an agent wrapper.
FROM scratch AS agent
ARG SOURCE_COMMIT
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT
COPY native-worker-probe /app/native-worker-probe
USER 65532:65532
ENTRYPOINT ["/app/native-worker-probe"]

FROM scratch AS controller
ARG SOURCE_COMMIT
LABEL org.opencontainers.image.revision=$SOURCE_COMMIT
COPY native-probe-service.test /app/native-probe-service.test
USER 65532:65532
ENTRYPOINT ["/app/native-probe-service.test"]
CMD ["-test.v=test2json", "-test.run=^TestNativeProbeActualClusterIPReverseSNATEcho$", "-test.timeout=5m"]
