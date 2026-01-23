#!/bin/bash

# Bash/Zsh Completion for ssh-ca-client

_ssh_ca_client_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="-url -key-file -identity -type"

    case "${prev}" in
        -type)
            COMPREPLY=( $(compgen -W "ed25519 ed25519-sk" -- ${cur}) )
            return 0
            ;;
        -key-file|-identity)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
    esac

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}

complete -F _ssh_ca_client_completion ssh-ca-client
