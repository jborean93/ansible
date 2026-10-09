# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = """
    name: default
    type: stdout
    short_description: default Ansible screen output
    version_added: historical
    description:
        - This is the default output callback for ansible-playbook.
    extends_documentation_fragment:
      - default_callback
      - result_format_callback
    requirements:
      - set as stdout in configuration
"""

import typing as _t

from ansible import constants as C
from ansible import context
from ansible.executor.task_result import CallbackTaskResult
from ansible.playbook.task_include import TaskInclude
from ansible.plugins.callback import CallbackBase
from ansible.utils.color import colorize, hostcolor
from ansible.utils.fqcn import add_internal_fqcns

if _t.TYPE_CHECKING:
    from ansible.playbook.included_file import IncludedFile


class CallbackModule(CallbackBase):

    """
    This is the default callback interface, which simply prints messages
    to stdout when new callback events are received.
    """

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'default'

    def __init__(self):

        self._play = None
        self._last_task_banner = None
        self._last_task_name = None
        self._task_type_cache = {}
        super(CallbackModule, self).__init__()

    def v2_runner_on_failed(self, result: CallbackTaskResult, ignore_errors: bool = False) -> None:
        host_label = self.host_label(result)

        if self._last_task_banner != result.task._uuid:
            self._print_task_banner(result.task)

        self._handle_warnings_and_exception(result)

        # FIXME: this method should not exist, delegate "suggested keys to display" to the plugin or something... As-is, the placement of this
        #          call obliterates `results`, which causes a task summary to be printed on loop failures, which we don't do anywhere else.
        self._clean_results(result.result, result.task.action)

        if result.task.loop and 'results' in result.result:
            self._process_items(result)
        else:
            if self._display.verbosity < 2 and self.get_option('show_task_path_on_failure'):
                self._print_task_path(result.task)
            msg = self._display.compose("fatal: [%s]: FAILED! => %s", host_label, self._dump_results(result.result))
            self._display.display(msg, color=C.COLOR_ERROR, stderr=self.get_option('display_failed_stderr'))

        if ignore_errors:
            self._display.display(self._display.compose("...ignoring"), color=C.COLOR_SKIP)

    def v2_runner_on_ok(self, result: CallbackTaskResult) -> None:
        host_label = self.host_label(result)

        if isinstance(result.task, TaskInclude):
            if self._last_task_banner != result.task._uuid:
                self._print_task_banner(result.task)
            return
        elif result.result.get('changed', False):
            if self._last_task_banner != result.task._uuid:
                self._print_task_banner(result.task)

            msg = self._display.compose("changed: [%s]", host_label)
            color = C.COLOR_CHANGED
        else:
            if not self.get_option('display_ok_hosts'):
                return

            if self._last_task_banner != result.task._uuid:
                self._print_task_banner(result.task)

            msg = self._display.compose("ok: [%s]", host_label)
            color = C.COLOR_OK

        self._handle_warnings_and_exception(result)

        if result.task.loop and 'results' in result.result:
            self._process_items(result)
        else:
            self._clean_results(result.result, result.task.action)

            if self._run_is_verbose(result):
                msg = self._display.compose("%s => %s", msg, self._dump_results(result.result))

            self._display.display(msg, color=color)

    def v2_runner_on_skipped(self, result: CallbackTaskResult) -> None:
        if self.get_option('display_skipped_hosts'):

            self._clean_results(result.result, result.task.action)

            if self._last_task_banner != result.task._uuid:
                self._print_task_banner(result.task)

            self._handle_warnings_and_exception(result)

            if result.task.loop is not None and 'results' in result.result:
                self._process_items(result)

            msg = self._display.compose("skipping: [%s]", self._mark_nonsensitive(result.host.get_name()))
            if self._run_is_verbose(result):
                msg = self._display.compose("%s => %s", msg, self._dump_results(result.result))
            self._display.display(msg, color=C.COLOR_SKIP)

    def v2_runner_on_unreachable(self, result: CallbackTaskResult) -> None:
        if self._last_task_banner != result.task._uuid:
            self._print_task_banner(result.task)

        self._handle_warnings_and_exception(result)

        host_label = self.host_label(result)
        msg = self._display.compose("fatal: [%s]: UNREACHABLE! => %s", host_label, self._dump_results(result.result))
        self._display.display(msg, color=C.COLOR_UNREACHABLE, stderr=self.get_option('display_failed_stderr'))

        if result.task.ignore_unreachable:
            self._display.display(self._display.compose("...ignoring"), color=C.COLOR_SKIP)

    def v2_playbook_on_no_hosts_matched(self):
        self._display.display(self._display.compose("skipping: no hosts matched"), color=C.COLOR_SKIP)

    def v2_playbook_on_no_hosts_remaining(self):
        self._display.banner(self._display.compose("NO MORE HOSTS LEFT"))

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._task_start(task, prefix='TASK')

    def _task_start(self, task, prefix=None):
        # Cache output prefix for task if provided
        # This is needed to properly display 'RUNNING HANDLER' and similar
        # when hiding skipped/ok task results
        if prefix is not None:
            self._task_type_cache[task._uuid] = prefix

        # Preserve task name, as all vars may not be available for templating
        # when we need it later
        if self._play.strategy in add_internal_fqcns(('free', 'host_pinned')):
            # Explicitly set to None for strategy free/host_pinned to account for any cached
            # task title from a previous non-free play
            self._last_task_name = None
        else:
            self._last_task_name = task.get_name().strip()

            # Display the task banner immediately if we're not doing any filtering based on task result
            if self.get_option('display_skipped_hosts') and self.get_option('display_ok_hosts'):
                self._print_task_banner(task)

    def _print_task_banner(self, task):
        # args can be specified as no_log in several places: in the task or in
        # the argument spec.  We can check whether the task is no_log but the
        # argument spec can't be because that is only run on the target
        # machine and we haven't run it there yet at this time.
        #
        # So we give people a config option to affect display of the args so
        # that they can secure this if they feel that their stdout is insecure
        # (shoulder surfing, logging stdout straight to a file, etc).
        args = ''
        # FIXME: the no_log value is not templated at this point, so any template will be considered truthy
        if not task.no_log and C.DISPLAY_ARGS_TO_STDOUT:
            args = u', '.join(u'%s=%s' % a for a in task.args.items())
            args = u' %s' % args

        prefix = self._task_type_cache.get(task._uuid, 'TASK')

        # Use cached task name
        task_name = self._last_task_name
        if task_name is None:
            task_name = task.get_name().strip()

        if task.check_mode and self.get_option('check_mode_markers'):
            checkmsg = " [CHECK MODE]"
        else:
            checkmsg = ""
        self._display.banner(self._display.compose(
            u"%s [%s%s]%s",
            self._mark_nonsensitive(prefix),
            task_name,
            args,
            self._mark_nonsensitive(checkmsg),
        ))

        if self._display.verbosity >= 2:
            self._print_task_path(task)

        self._last_task_banner = task._uuid

    def v2_playbook_on_handler_task_start(self, task):
        self._task_start(task, prefix='RUNNING HANDLER')

    def v2_runner_on_start(self, host, task):
        if self.get_option('show_per_host_start'):
            self._display.display(self._display.compose(" [started %s on %s]", task, self._mark_nonsensitive(str(host))), color=C.COLOR_OK)

    def v2_playbook_on_play_start(self, play):
        name = play.get_name().strip()
        if play.check_mode and self.get_option('check_mode_markers'):
            checkmsg = " [CHECK MODE]"
        else:
            checkmsg = ""
        if not name:
            msg = self._display.compose(u"PLAY%s", self._mark_nonsensitive(checkmsg))
        else:
            msg = self._display.compose(u"PLAY [%s]%s", name, self._mark_nonsensitive(checkmsg))

        self._play = play

        self._display.banner(msg)

    def v2_on_file_diff(self, result: CallbackTaskResult) -> None:
        if result.task.loop and 'results' in result.result:
            for res in result.result['results']:
                if 'diff' in res and res['diff'] and res.get('changed', False):
                    diff = self._get_diff(res['diff'])
                    if diff:
                        if self._last_task_banner != result.task._uuid:
                            self._print_task_banner(result.task)
                        self._display.display(diff)
        elif 'diff' in result.result and result.result['diff'] and result.result.get('changed', False):
            diff = self._get_diff(result.result['diff'])
            if diff:
                if self._last_task_banner != result.task._uuid:
                    self._print_task_banner(result.task)
                self._display.display(diff)

    def v2_runner_item_on_ok(self, result: CallbackTaskResult) -> None:
        host_label = self.host_label(result)
        if isinstance(result.task, TaskInclude):
            return
        elif result.result.get('changed', False):
            if self._last_task_banner != result.task._uuid:
                self._print_task_banner(result.task)

            template = "changed: [%s] => (item=%s)"
            color = C.COLOR_CHANGED
        else:
            if not self.get_option('display_ok_hosts'):
                return

            if self._last_task_banner != result.task._uuid:
                self._print_task_banner(result.task)

            template = "ok: [%s] => (item=%s)"
            color = C.COLOR_OK

        self._handle_warnings_and_exception(result)

        msg = self._display.compose(template, host_label, self._get_item_label(result.result))
        self._clean_results(result.result, result.task.action)
        if self._run_is_verbose(result):
            msg = self._display.compose("%s => %s", msg, self._dump_results(result.result))

        self._display.display(msg, color=color)

    def v2_runner_item_on_failed(self, result: CallbackTaskResult) -> None:
        if self._last_task_banner != result.task._uuid:
            self._print_task_banner(result.task)

        self._handle_warnings_and_exception(result)

        host_label = self.host_label(result)

        self._clean_results(result.result, result.task.action)
        self._display.display(
            self._display.compose(
                "failed: [%s] (item=%s) => %s",
                host_label,
                self._get_item_label(result.result),
                self._dump_results(result.result),
            ),
            color=C.COLOR_ERROR,
            stderr=self.get_option('display_failed_stderr')
        )

    def v2_runner_item_on_skipped(self, result: CallbackTaskResult) -> None:
        if self.get_option('display_skipped_hosts'):
            if self._last_task_banner != result.task._uuid:
                self._print_task_banner(result.task)

            self._handle_warnings_and_exception(result)

            self._clean_results(result.result, result.task.action)
            msg = self._display.compose(
                "skipping: [%s] => (item=%s) ",
                self._mark_nonsensitive(result.host.get_name()),
                self._get_item_label(result.result),
            )
            if self._run_is_verbose(result):
                msg = self._display.compose("%s => %s", msg, self._dump_results(result.result))
            self._display.display(msg, color=C.COLOR_SKIP)

    def v2_playbook_on_include(self, included_file: IncludedFile) -> None:
        if not self.get_option("display_included_hosts"):
            return

        msg = self._display.compose(
            'included: %s for %s',
            self._mark_nonsensitive(included_file._filename),
            self._mark_nonsensitive(", ".join([h.name for h in included_file._hosts])),
        )
        label = self._get_item_label(included_file._vars)
        if label:
            # unlike item labels elsewhere in this callback, these vars never passed through `mask_object`
            msg = self._display.compose("%s => (item=%s)", msg, label)
        self._display.display(msg, color=C.COLOR_INCLUDED)

    def v2_playbook_on_stats(self, stats):
        self._display.banner(self._display.compose("PLAY RECAP"))

        hosts = sorted(stats.processed.keys())

        for h in hosts:
            t = stats.summarize(h)
            self._display.display(
                self._mark_nonsensitive(
                    u"%s : %s %s %s %s %s %s %s" % (
                        hostcolor(h, t),
                        colorize(u'ok', t['ok'], C.COLOR_OK),
                        colorize(u'changed', t['changed'], C.COLOR_CHANGED),
                        colorize(u'unreachable', t['unreachable'], C.COLOR_UNREACHABLE),
                        colorize(u'failed', t['failures'], C.COLOR_ERROR),
                        colorize(u'skipped', t['skipped'], C.COLOR_SKIP),
                        colorize(u'rescued', t['rescued'], C.COLOR_OK),
                        colorize(u'ignored', t['ignored'], C.COLOR_WARN),
                    )
                ),
                screen_only=True
            )

            self._display.display(
                self._mark_nonsensitive(
                    u"%s : %s %s %s %s %s %s %s" % (
                        hostcolor(h, t, False),
                        colorize(u'ok', t['ok'], None),
                        colorize(u'changed', t['changed'], None),
                        colorize(u'unreachable', t['unreachable'], None),
                        colorize(u'failed', t['failures'], None),
                        colorize(u'skipped', t['skipped'], None),
                        colorize(u'rescued', t['rescued'], None),
                        colorize(u'ignored', t['ignored'], None),
                    )
                ),
                log_only=True
            )

        self._display.display("", screen_only=True)

        # print custom stats if required
        if stats.custom and self.get_option('show_custom_stats'):
            self._display.banner(self._display.compose("CUSTOM STATS: "))
            # per host
            # TODO: come up with 'pretty format'
            for k in sorted(stats.custom.keys()):
                if k == '_run':
                    continue
                # custom stats never passed through `mask_object`, so the key is data too
                self._display.display(self._display.compose('\t%s: %s', k, self._dump_results(stats.custom[k], indent=1).replace('\n', '')))

            # print per run custom stats
            if '_run' in stats.custom:
                self._display.display("", screen_only=True)
                self._display.display(self._display.compose('\tRUN: %s', self._dump_results(stats.custom['_run'], indent=1).replace('\n', '')))
            self._display.display("", screen_only=True)

        if context.CLIARGS['check'] and self.get_option('check_mode_markers'):
            self._display.banner(self._display.compose("DRY RUN"))

    def v2_playbook_on_start(self, playbook):
        if self._display.verbosity > 1:
            from os.path import basename
            self._display.banner(self._display.compose("PLAYBOOK: %s", self._mark_nonsensitive(basename(playbook._file_name))))

        # show CLI arguments
        if self._display.verbosity > 3:
            if context.CLIARGS.get('args'):
                self._display.display('Positional arguments: %s' % ' '.join(context.CLIARGS['args']),
                                      color=C.COLOR_VERBOSE, screen_only=True)

            for argument in (a for a in context.CLIARGS if a != 'args'):
                val = context.CLIARGS[argument]
                if val:
                    self._display.display('%s: %s' % (argument, val), color=C.COLOR_VERBOSE, screen_only=True)

        if context.CLIARGS['check'] and self.get_option('check_mode_markers'):
            self._display.banner(self._display.compose("DRY RUN"))

    def v2_runner_retry(self, result: CallbackTaskResult) -> None:
        task_name = result.task_name or result.task
        host_label = self.host_label(result)
        msg = self._display.compose(
            "FAILED - RETRYING: [%s]: %s (%s retries left).",
            host_label,
            task_name,
            result.result['retries'] - result.result['attempts'],
        )
        if self._run_is_verbose(result, verbosity=2):
            msg = self._display.compose("%sResult was: %s", msg, self._dump_results(result.result))
        self._display.display(msg, color=C.COLOR_DEBUG)

    def v2_runner_on_async_poll(self, result: CallbackTaskResult) -> None:
        host = result.host.get_name()
        jid = result.result.get('ansible_job_id')
        started = result.result.get('started')
        finished = result.result.get('finished')
        self._display.display(
            self._display.compose('ASYNC POLL on %s: jid=%s started=%s finished=%s', self._mark_nonsensitive(host), jid, started, finished),
            color=C.COLOR_DEBUG
        )

    def v2_runner_on_async_ok(self, result: CallbackTaskResult) -> None:
        host = result.host.get_name()
        jid = result.result.get('ansible_job_id')
        self._display.display(self._display.compose("ASYNC OK on %s: jid=%s", self._mark_nonsensitive(host), jid), color=C.COLOR_DEBUG)

    def v2_runner_on_async_failed(self, result: CallbackTaskResult) -> None:
        host = result.host.get_name()

        # Attempt to get the async job ID. If the job does not finish before the
        # async timeout value, the ID may be within the unparsed 'async_result' dict.
        jid = result.result.get('ansible_job_id')
        if not jid and 'async_result' in result.result:
            jid = result.result['async_result'].get('ansible_job_id')
        self._display.display(self._display.compose("ASYNC FAILED on %s: jid=%s", self._mark_nonsensitive(host), jid), color=C.COLOR_DEBUG)

    def v2_playbook_on_notify(self, handler, host):
        if self._display.verbosity > 1:
            self._display.display(
                self._display.compose("NOTIFIED HANDLER %s for %s", handler.get_name(), self._mark_nonsensitive(str(host))),
                color=C.COLOR_VERBOSE,
                screen_only=True,
            )
