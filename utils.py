#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import sys
import tempfile
import os
import uuid
import json
import stat
from git import Repo
from git import NULL_TREE


def return_results(results, results_dir, issues_results):
    for issue_results in issues_results:
        result_path = os.path.join(results_dir, str(uuid.uuid4()))
        with open(result_path, "w+") as result_file:
            result_file.write(json.dumps(issue_results))
        results["issues_results"].append(result_path)
    return results

def path_included(blob, include_patterns=None):
    path = blob.b_path if blob.b_path else blob.a_path
    if include_patterns and not any(p.match(path) for p in include_patterns):
        return False
    return True


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def colorize(val, code):
    return '\x1b[{}m{}\x1b[0m'.format(code, val)


def print_results(issue):
    commit_time = issue['date']
    branch_name = issue['branch']
    raw_diff = issue['printDiff']
    commit_hash = issue['commit_hash']
    scan_type = issue['reason']
    path = issue['path']

    #print("---------------------------------------")
    scan_type = "\n{}Scan_type: {}{}".format(bcolors.OKGREEN, scan_type, bcolors.ENDC)
    print(scan_type)
    dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
    print(dateStr)
    hashStr = "{}Commit Hash: {}{}".format(bcolors.OKGREEN, commit_hash, bcolors.ENDC)
    print(hashStr)
    filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
    print(filePath)
    if sys.version_info >= (3, 0):
        branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
        print(branchStr + "\n")
        print('{}{}{}\n'.format(bcolors.BOLD, raw_diff, bcolors.ENDC))
    else:
        branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
        print(branchStr + "\n")
        print('{}{}{}\n'.format(bcolors.BOLD, raw_diff.encode('utf-8'), bcolors.ENDC))
    #print("---------------------------------------")
