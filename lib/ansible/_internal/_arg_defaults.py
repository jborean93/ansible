from __future__ import annotations

import typing as t

from ansible._internal._templating._engine import TemplateEngine
from ansible.template import Templar

if t.TYPE_CHECKING:
    from ansible.playbook.task import Task

from ansible.utils.display import Display

display = Display()


def get_action_arg_defaults(action: str, task: Task, templar: TemplateEngine) -> dict[str, t.Any]:
    action_groups = task._parent._play._action_groups
    defaults = task.module_defaults

    # Get the list of groups that contain this action
    if action_groups is None:
        msg = (
            "Finding module_defaults for action %s. "
            "The caller has not passed the action_groups, so any "
            "that may include this action will be ignored."
        )
        display.warning(msg=msg)
        group_names = []
    else:
        group_names = action_groups.get(action, [])

    tmp_args: dict[str, t.Any] = {}
    module_defaults = {}

    # Merge latest defaults into dict, since they are a list of dicts
    if isinstance(defaults, list):
        for default in defaults:
            module_defaults.update(default)

    for default in module_defaults:
        if default.startswith('group/'):
            group_name = default.split('group/')[-1]
            if group_name in group_names:
                tmp_args.update(templar.resolve_to_container(module_defaults.get(f'group/{group_name}', {})))

    # handle specific action defaults
    tmp_args.update(templar.resolve_to_container(module_defaults.get(action, {})))

    return tmp_args


def apply_action_arg_defaults(action: str, task: Task, action_args: dict[str, t.Any], templar: Templar) -> dict[str, t.Any]:
    args = get_action_arg_defaults(action, task, templar._engine)
    args.update(action_args)

    return args
