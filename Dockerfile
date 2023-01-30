FROM openeuler/openeuler:22.03-lts-sp1
WORKDIR /app
COPY *.repo  /app/
RUN dnf install aops-apollo -y --setopt=reposdir=/app
ENTRYPOINT ["nohup","aops-apollo","&"]