{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = with pkgs; [
    perl
    curl
    docker
    docker-compose
    jq
    git
  ];

  shellHook = ''
    echo "VSAT honeypot dev shell"
    echo "Available tools: perl, curl, docker, docker-compose, jq, git"
    echo "Run: perl server.pl"
    echo "Or:  docker compose up -d --build"
  '';
}
