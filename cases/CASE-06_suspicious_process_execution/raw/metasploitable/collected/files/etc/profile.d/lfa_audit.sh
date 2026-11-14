export HISTTIMEFORMAT="%F %T "
export PROMPT_COMMAND='logger -p local6.info -t bash "$(whoami)[$$]: $(history 1 | sed s/^[0-9\ ]*//)"'
