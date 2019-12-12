#!/usr/bin/env bash
# bash completion for envelope
_envelope()
{
  local cur
  local cmd

  cur=${COMP_WORDS[$COMP_CWORD]}
  prev="${COMP_WORDS[COMP_CWORD-1]}";
  cmd=( ${COMP_WORDS[@]} )

  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $( compgen -W "--help --message --input --output --gpg --smime --check --sign --cert --passphrase --sign-path --cert-path --encrypt --encrypt-path --to --cc --bcc --reply-to --from --sender --sender --no-sender --attachment --attach-key --send --subject --smtp --smtp --header" -- $cur ) )
    return 0
  fi
}

complete -F _envelope -o default envelope
